package com.tracepcap.knowledge.dto;

import com.tracepcap.knowledge.dto.CaseKnowledgeResponse.EntityRefDto;
import com.tracepcap.knowledge.spi.Goal;
import com.tracepcap.knowledge.spi.InvestigationReport;
import java.util.List;

/** API view of an autonomous investigation report (#819, L2). */
public record InvestigationReportResponse(
    List<GoalOutcomeDto> goals,
    List<AnswerResponse> additional,
    List<String> unknowns,
    List<String> coverage,
    List<ConsideredResponse> considered) {

  /** A candidate a check tested and ruled out (#1294), with why. */
  public record ConsideredResponse(
      String question, String candidate, String rule, String reason, List<String> conversations) {}


  public static InvestigationReportResponse from(InvestigationReport report) {
    return new InvestigationReportResponse(
        report.outcomes().stream().map(GoalOutcomeDto::from).toList(),
        report.additional().stream().map(AnswerResponse::from).toList(),
        report.openGoals().stream().map(Goal::name).toList(),
        report.coverage(),
        report.considered().stream()
            .map(c -> new ConsideredResponse(c.question(), c.candidate(), c.rule(), c.reason(), c.conversations()))
            .toList());
  }

  public record GoalOutcomeDto(
      String goal,
      boolean answered,
      String headline,
      String grade,
      int confidence,
      List<String> basis,
      List<EntityRefDto> subjects,
      java.util.Map<String, Object> attributes,
      List<AnswerResponse.StepResponse> derivation) {

    public static GoalOutcomeDto from(InvestigationReport.GoalOutcome o) {
      return new GoalOutcomeDto(
          o.goal().name(),
          o.answered(),
          o.headline(),
          o.grade() == null ? null : o.grade().name(),
          o.confidence(),
          o.basis(),
          o.subjects().stream().map(EntityRefDto::from).toList(),
          o.attributes(),
          o.derivation().stream()
              .map(s -> new AnswerResponse.StepResponse(s.found(), s.rule(), s.grade().name(), s.conversations()))
              .toList());
    }
  }
}
