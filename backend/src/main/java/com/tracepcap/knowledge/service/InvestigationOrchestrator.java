package com.tracepcap.knowledge.service;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
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
            goal, true, a.headline(), a.grade(), confidenceFor(a.grade()), a.basis(), a.subjects(),
            a.attributes(), a.derivation()));
      }
    }
    // Every answer that is not the one representing a goal still belongs in the report: a non-goal
    // answer (a bulk transfer to review), but equally the 2nd..nth answer for a goal — a second C2,
    // a second malware family, another victim host. The panel renders from here, so dropping them
    // would hide real findings that /answers and the narrative both show.
    List<Answer> additional = answers.stream().filter(a -> !representing.contains(a)).toList();
    return new InvestigationReport(fileId, outcomes, additional, coverage(board), considered(board));
  }

  /**
   * Every candidate a check tested and ruled out on this board (#1294): what contributors posted,
   * and beacons whose server didn't end up a C2. The report, the narrative and Q&A all read this.
   */
  public static List<com.tracepcap.knowledge.spi.Considered> considered(CaseKnowledge board) {
    List<com.tracepcap.knowledge.spi.Considered> out = new ArrayList<>(
        board.findingsOfCategory(com.tracepcap.knowledge.spi.Considered.CATEGORY).stream()
            .map(com.tracepcap.knowledge.spi.Considered::from)
            .filter(java.util.Objects::nonNull)
            .toList());
    out.addAll(unclassifiedBeacons(board));
    // One per question and candidate: a listed server that also beacons is one alternative.
    java.util.Map<List<String>, com.tracepcap.knowledge.spi.Considered> once = new java.util.LinkedHashMap<>();
    for (com.tracepcap.knowledge.spi.Considered c : out) once.putIfAbsent(List.of(c.question(), c.candidate()), c);
    return new ArrayList<>(once.values());
  }

  static final String BEACON_RULE =
      "A beacon is a C2 only when a rule names its server or its stream opens with a known malware"
          + " family's check-in; a regular, quiet connection alone is also what update checks and"
          + " telemetry look like.";

  /**
   * Beacons whose server didn't end up a C2 (#1294): judged after the pivots, so a beacon the
   * stream classifier did match isn't listed. One per server.
   */
  static List<com.tracepcap.knowledge.spi.Considered> unclassifiedBeacons(CaseKnowledge board) {
    Set<EntityRef> c2s = new java.util.HashSet<>();
    board.relationshipsWithPredicate("c2-of").forEach(r -> c2s.add(r.from()));
    java.util.Map<String, com.tracepcap.knowledge.spi.Considered> out = new java.util.LinkedHashMap<>();
    for (com.tracepcap.knowledge.spi.Finding f : board.findingsOfCategory("suspected-beacon")) {
      EntityRef ext = f.concerns().stream()
          .filter(r -> r.type() == com.tracepcap.knowledge.spi.EntityType.EXTERNAL_SERVICE)
          .findFirst().orElse(null);
      if (ext == null || c2s.contains(ext) || out.containsKey(ext.key())) continue;
      out.put(ext.key(), new com.tracepcap.knowledge.spi.Considered("c2", ext.key(), BEACON_RULE,
          "a beacon (" + f.summary() + "), but no rule named it and no known family's check-in was"
              + " found in its stream.", f.evidence()));
    }
    return new ArrayList<>(out.values());
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
    // A ruled-out candidate isn't a contribution: the technique concluded nothing (#1294).
    board.findings().stream()
        .filter(f -> !com.tracepcap.knowledge.spi.Considered.CATEGORY.equals(f.category()))
        .forEach(f -> add(sources, f.source()));
    return new ArrayList<>(sources);
  }

  private static void add(TreeSet<String> set, String s) {
    if (s != null && !s.isBlank()) set.add(s);
  }
}
