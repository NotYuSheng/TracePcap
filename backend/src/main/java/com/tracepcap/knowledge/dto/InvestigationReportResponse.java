package com.tracepcap.knowledge.dto;

import com.tracepcap.knowledge.dto.CaseKnowledgeResponse.EntityRefDto;
import com.tracepcap.knowledge.spi.Goal;
import com.tracepcap.knowledge.spi.InvestigationReport;
import java.util.List;

/** API view of an autonomous investigation report (#819, L2). */
public record InvestigationReportResponse(
    List<GoalOutcomeDto> goals, List<String> unknowns, List<String> coverage) {

  public static InvestigationReportResponse from(InvestigationReport report) {
    return new InvestigationReportResponse(
        report.outcomes().stream().map(GoalOutcomeDto::from).toList(),
        report.openGoals().stream().map(Goal::name).toList(),
        report.coverage());
  }

  public record GoalOutcomeDto(
      String goal,
      boolean answered,
      String headline,
      String grade,
      int confidence,
      List<String> basis,
      List<EntityRefDto> subjects) {

    public static GoalOutcomeDto from(InvestigationReport.GoalOutcome o) {
      return new GoalOutcomeDto(
          o.goal().name(),
          o.answered(),
          o.headline(),
          o.grade() == null ? null : o.grade().name(),
          o.confidence(),
          o.basis(),
          o.subjects().stream().map(EntityRefDto::from).toList());
    }
  }
}
