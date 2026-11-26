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
    List<ConsideredResponse> considered,
    // Every framework category's status on this capture, with where to look.
    List<CategoryStatusResponse> categories) {

  /** One investigation-framework category on this capture. */
  public record CategoryStatusResponse(
      String key,
      String axis,
      String label,
      String attackId,
      String status,
      boolean unchecked,
      String reason,
      List<CategoryLeadResponse> leads) {

    public static CategoryStatusResponse from(
        com.tracepcap.knowledge.service.CategoryCoverage.CategoryStatus s) {
      var c = s.category();
      return new CategoryStatusResponse(c.key(), c.axis().name(), c.label(), c.attackId(),
          s.status().name(), s.unchecked(), s.reason(),
          s.leads().stream().map(l -> new CategoryLeadResponse(l.label(), l.shows(), l.query())).toList());
    }
  }

  /** A protocol in this capture worth a look for a category: what it shows, and its conversations. */
  public record CategoryLeadResponse(String label, String shows, String query) {}

  /** A candidate a check tested and ruled out (#1294), with why. */
  public record ConsideredResponse(
      String question, String candidate, String rule, String reason, List<String> conversations) {}


  public static InvestigationReportResponse from(InvestigationReport report) {
    return from(report, List.of());
  }

  public static InvestigationReportResponse from(
      InvestigationReport report,
      List<com.tracepcap.knowledge.service.CategoryCoverage.CategoryStatus> categories) {
    return new InvestigationReportResponse(
        report.outcomes().stream().map(GoalOutcomeDto::from).toList(),
        report.additional().stream().map(AnswerResponse::from).toList(),
        report.openGoals().stream().map(Goal::name).toList(),
        report.coverage(),
        report.considered().stream()
            .map(c -> new ConsideredResponse(c.question(), c.candidate(), c.rule(), c.reason(), c.conversations()))
            .toList(),
        categories.stream().map(CategoryStatusResponse::from).toList());
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
