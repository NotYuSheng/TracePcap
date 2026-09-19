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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
    CaseKnowledge board = runPivots(fileId, caseKnowledgeService.assemble(fileId));
    return report(fileId, board, standardQuestionService.answer(board));
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
        try {
          pivot.pivot(current, out);
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
    for (Goal goal : Goal.values()) {
      Answer a = byQuestion.get(goal.questionKey());
      if (a == null) {
        outcomes.add(new GoalOutcome(goal, false, null, null, 0, List.of(), List.of()));
      } else {
        outcomes.add(new GoalOutcome(
            goal, true, a.headline(), a.grade(), confidenceFor(a.grade()), a.basis(), a.subjects()));
      }
    }
    return new InvestigationReport(fileId, outcomes, coverage(board));
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
