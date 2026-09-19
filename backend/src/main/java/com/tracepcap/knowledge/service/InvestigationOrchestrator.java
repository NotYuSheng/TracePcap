package com.tracepcap.knowledge.service;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.Goal;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.InvestigationReport;
import com.tracepcap.knowledge.spi.InvestigationReport.GoalOutcome;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * The autonomous investigation orchestrator (#819, L2). It assembles the knowledge board, runs the
 * deterministic techniques, and reports every standing {@link Goal} as answered-or-open with a
 * confidence and the techniques that contributed.
 *
 * <p>L2 is deliberately <b>deterministic and LLM-free</b>: the orchestrator's autonomy is the goal
 * model, not a language model. It does not detect (the techniques do) and it does not narrate — that
 * is a downstream consumer. The pivot loop that chains techniques toward an open goal (beacon →
 * follow-stream → classify) arrives in the next increment; today the goals are closed by the
 * producers already on the board, and the value is the first-class, honest <em>unknowns</em> list.
 */
@Service
@RequiredArgsConstructor
public class InvestigationOrchestrator {

  private final CaseKnowledgeService caseKnowledgeService;
  private final StandardQuestionService standardQuestionService;

  public InvestigationReport investigate(UUID fileId) {
    CaseKnowledge board = caseKnowledgeService.assemble(fileId);
    return report(fileId, board, standardQuestionService.answer(board));
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
