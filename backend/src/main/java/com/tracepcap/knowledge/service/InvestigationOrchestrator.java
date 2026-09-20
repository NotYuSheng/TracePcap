package com.tracepcap.knowledge.service;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.Goal;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.InvestigationReport;
import com.tracepcap.knowledge.spi.InvestigationReport.GoalOutcome;
import com.tracepcap.knowledge.spi.InvestigativePivot;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * The autonomous investigation orchestrator (#819, L2). It assembles the knowledge board, runs the
 * deterministic techniques, and reports every standing {@link Goal} as answered-or-open with a
 * confidence and the techniques that contributed.
 *
 * <p>L2 is deliberately <b>deterministic and LLM-free</b>: the orchestrator's autonomy is the goal
 * model, not a language model. It does not detect (the techniques do) and it does not narrate — that
 * is a downstream consumer. It assembles the board, then runs {@link InvestigativePivot}s that follow
 * leads (beacon → follow-stream → classify) to a fixpoint, so a goal a producer could not close gets
 * closed; and it reports the goals still open as first-class, honest <em>unknowns</em>.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class InvestigationOrchestrator {

  /** Safety bound on the pivot loop; pivots are idempotent, so a couple of rounds always suffices. */
  private static final int MAX_PIVOT_ROUNDS = 4;

  private final CaseKnowledgeService caseKnowledgeService;
  private final StandardQuestionService standardQuestionService;
  private final List<InvestigativePivot> pivots;

  public InvestigationReport investigate(UUID fileId) {
    CaseKnowledge board = investigatedBoard(fileId);
    return report(fileId, board, standardQuestionService.answer(board));
  }

  /**
   * The board after the pivot loop — the full picture, including what pivots derived (a classified
   * C2, say) that plain {@code assemble} does not carry. Consumers that want the complete knowledge
   * (the narrative's ground truth, the Q&A digest, the Investigation Summary) read this rather than
   * {@code /answers}, which is producer-only.
   *
   * <p><b>Cost.</b> Beyond the {@code assemble} that {@code /answers} also pays, this adds one
   * bounded read (a LIMITed payload query) per suspected beacon followed, capped per pass — usually
   * zero, since most captures have no suspected beacon. Nothing is cached: the board is derived from
   * facts that human overrides and re-analysis can change, and a stale conclusion here would be worse
   * than a cheap recompute. Caching is a separate decision (#816).
   */
  public CaseKnowledge investigatedBoard(UUID fileId) {
    return runPivots(fileId, caseKnowledgeService.assemble(fileId));
  }

  /**
   * Runs applicable pivots against the board until none applies or the board stops changing.
   * Each pivot is isolated — one that throws is logged and skipped, never failing the investigation.
   */
  private CaseKnowledge runPivots(UUID fileId, CaseKnowledge board) {
    for (int round = 0; round < MAX_PIVOT_ROUNDS; round++) {
      CaseKnowledge current = board; // effectively final for the lambda / pivot calls below
      List<InvestigativePivot> applicable =
          pivots.stream().filter(p -> safeApplies(p, current)).toList();
      if (applicable.isEmpty()) break;

      CaseKnowledgeBuilder out = new CaseKnowledgeBuilder(fileId).addAll(current);
      for (InvestigativePivot pivot : applicable) {
        // Each pivot writes to its own scratch builder and is merged only if it completes, so one
        // that throws midway leaves nothing half-applied on the shared board.
        CaseKnowledgeBuilder scratch = new CaseKnowledgeBuilder(fileId);
        try {
          pivot.pivot(current, scratch);
          out.addAll(scratch.build());
        } catch (Exception e) {
          log.warn("Pivot '{}' failed for file {}: {}", pivot.name(), fileId, e.getMessage());
        }
      }
      CaseKnowledge next = out.build();
      if (size(next) == size(current)) break; // fixpoint — nothing new was added
      board = next;
    }
    return board;
  }

  private static boolean safeApplies(InvestigativePivot pivot, CaseKnowledge board) {
    try {
      return pivot.appliesTo(board);
    } catch (Exception e) {
      // Logged: silently dropping a pivot would make the investigation look like it simply had no
      // lead to follow, with nothing to say otherwise.
      log.warn("Pivot '{}' appliesTo failed, skipping it: {}", pivot.name(), e.getMessage());
      return false;
    }
  }

  private static int size(CaseKnowledge b) {
    return b.entities().size() + b.relationships().size() + b.findings().size();
  }

  /** Board-in / report-out seam, so the goal logic is unit-testable without a file or the DB. */
  InvestigationReport report(UUID fileId, CaseKnowledge board, List<Answer> answers) {
    // First answer wins per question — the questions already emit their strongest first.
    Map<String, Answer> byQuestion = new LinkedHashMap<>();
    for (Answer a : answers) byQuestion.putIfAbsent(a.question(), a);

    List<GoalOutcome> outcomes = new ArrayList<>();
    Set<Answer> representing = Collections.newSetFromMap(new IdentityHashMap<>());
    for (Goal goal : Goal.values()) {
      Answer a = byQuestion.get(goal.questionKey());
      if (a == null) {
        outcomes.add(new GoalOutcome(goal, false, null, null, 0, List.of(), List.of()));
      } else {
        representing.add(a);
        outcomes.add(new GoalOutcome(
            goal, true, a.headline(), a.grade(), confidenceFor(a.grade()), a.basis(), a.subjects()));
      }
    }
    // Every answer that is not the one representing a goal still belongs in the report: a non-goal
    // answer (a bulk transfer to review), but equally the 2nd..nth answer for a goal — a second C2,
    // a second malware family, another victim host. The panel renders from here, so dropping them
    // would hide real findings that /answers and the narrative both show.
    List<Answer> additional = answers.stream().filter(a -> !representing.contains(a)).toList();
    return new InvestigationReport(fileId, outcomes, additional, coverage(board));
  }

  /** Confidence follows the evidence grade — how directly the conclusion is known. */
  private static int confidenceFor(Grade grade) {
    return switch (grade) {
      case MEASURED -> 90;
      case REPORTED -> 70;
      case INFERRED -> 55;
    };
  }

  /** The techniques that actually contributed — the distinct artifact sources on the board. */
  private static List<String> coverage(CaseKnowledge board) {
    TreeSet<String> sources = new TreeSet<>();
    board.relationships().forEach(r -> add(sources, r.source()));
    board.findings().forEach(f -> add(sources, f.source()));
    return new ArrayList<>(sources);
  }

  private static void add(TreeSet<String> set, String s) {
    if (s != null && !s.isBlank()) set.add(s);
  }
}
