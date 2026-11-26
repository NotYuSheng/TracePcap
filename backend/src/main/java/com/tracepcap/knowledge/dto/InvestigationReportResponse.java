package com.tracepcap.knowledge.dto;

import com.tracepcap.knowledge.dto.CaseKnowledgeResponse.EntityRefDto;
import com.tracepcap.knowledge.service.CaptureContextService;
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
    List<CategoryStatusResponse> categories,
    // What the capture can show: where it was taken, how complete it is, the time it spans. Null
    // when not computed.
    CaptureContextResponse context) {

  /** Where the capture was taken, how complete it is, and the time it spans. */
  public record CaptureContextResponse(
      VantageResponse vantage, CompletenessResponse completeness, TimeSpanResponse timeSpan) {

    public static CaptureContextResponse from(CaptureContextService.CaptureContext c) {
      if (c == null) return null;
      var v = c.vantage();
      var q = c.completeness();
      var t = c.timeSpan();
      return new CaptureContextResponse(
          new VantageResponse(v.key(), v.label(), v.host(), v.basis(), v.confidence(), v.contested(),
              v.candidates().stream()
                  .map(k -> new VantageCandidateResponse(k.label(), k.score(), k.reasons())).toList(),
              v.reason(), v.overriddenBy(), CaptureContextService.QUESTION, CaptureContextService.ENTITY,
              java.util.Arrays.stream(CaptureContextService.Vantage.values())
                  .map(CaptureContextService.Vantage::label).toList()),
          new CompletenessResponse(q.label(), q.level(),
              q.notes().stream().map(n -> new QualityNoteResponse(n.kind(), n.level(), n.text())).toList()),
          new TimeSpanResponse(t.start(), t.end(), t.durationMs(), t.label()));
    }
  }

  /**
   * Where the capture was taken: an inferred vote an analyst can override or add evidence to, at
   * the adjudication endpoints for {@code question} and {@code entityKey}.
   *
   * @param key lan, uplink, client, server, sensor, "other" (an analyst's own), or null: undetermined
   * @param basis MACHINE (inferred) or HUMAN (overridden)
   * @param options the labels an analyst can pick from
   */
  public record VantageResponse(
      String key,
      String label,
      String host,
      String basis,
      int confidence,
      boolean contested,
      List<VantageCandidateResponse> candidates,
      String reason,
      String overriddenBy,
      String question,
      String entityKey,
      List<String> options) {}

  public record VantageCandidateResponse(String label, int score, List<String> reasons) {}

  /** {@code level}: complete, partial (traffic missing or uninspected) or notes. */
  public record CompletenessResponse(String label, String level, List<QualityNoteResponse> notes) {}

  public record QualityNoteResponse(String kind, String level, String text) {}

  public record TimeSpanResponse(
      java.time.LocalDateTime start, java.time.LocalDateTime end, Long durationMs, String label) {}

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
    return from(report, List.of(), null);
  }

  public static InvestigationReportResponse from(
      InvestigationReport report,
      List<com.tracepcap.knowledge.service.CategoryCoverage.CategoryStatus> categories,
      CaptureContextService.CaptureContext context) {
    return new InvestigationReportResponse(
        report.outcomes().stream().map(GoalOutcomeDto::from).toList(),
        report.additional().stream().map(AnswerResponse::from).toList(),
        report.openGoals().stream().map(Goal::name).toList(),
        report.coverage(),
        report.considered().stream()
            .map(c -> new ConsideredResponse(c.question(), c.candidate(), c.rule(), c.reason(), c.conversations()))
            .toList(),
        categories.stream().map(CategoryStatusResponse::from).toList(),
        CaptureContextResponse.from(context));
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
