package com.tracepcap.story.service;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.story.dto.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class InvestigationService {

  private final ConversationLookup conversationLookup;

  /** Free-text path: the model's queries need the full set of repairs. */
  public List<InvestigationStep> executeQueries(
      UUID fileId, List<InvestigationQuery> queries, List<Hypothesis> hypotheses) {
    return executeQueries(fileId, queries, hypotheses, false);
  }

  /**
   * @param schemaConstrained whether the queries came from schema-constrained tool calls, which
   *     changes how much repair {@link InvestigationQuerySanitizer} applies before execution
   */
  public List<InvestigationStep> executeQueries(
      UUID fileId,
      List<InvestigationQuery> queries,
      List<Hypothesis> hypotheses,
      boolean schemaConstrained) {

    List<InvestigationStep> steps = new ArrayList<>();
    List<InvestigationQuery> capped = queries.stream().limit(5).collect(Collectors.toList());

    for (InvestigationQuery raw : capped) {
      var sanitized = InvestigationQuerySanitizer.sanitize(raw, schemaConstrained);
      InvestigationQuery query = sanitized.query();

      if (InvestigationQuerySanitizer.isCatchAll(sanitized)) {
        log.warn("Skipping catch-all investigation query: {}", query.getId());
        continue;
      }

      try {
        Hypothesis linked =
            hypotheses.stream()
                .filter(h -> query.getId() != null && query.getId().equals(h.getQueryRef()))
                .findFirst()
                .orElse(null);

        var page = conversationLookup.conversationPage(fileId, 1, 10, toFilter(sanitized));

        List<ConversationEvidence> evidence =
            page.content().stream().map(this::toEvidence).collect(Collectors.toList());

        steps.add(
            InvestigationStep.builder()
                .query(query)
                .hypothesis(linked)
                .conversations(evidence)
                .conversationCount(page.totalElements())
                .build());

        log.info(
            "Query '{}' ({}): {} total matches, returning {}",
            query.getId(),
            query.getLabel(),
            page.totalElements(),
            evidence.size());
      } catch (Exception e) {
        log.error("Failed to execute investigation query '{}': {}", query.getId(), e.getMessage());
      }
    }

    return steps;
  }

  /**
   * Maps a sanitized, LLM-produced query onto the shared conversation filter.
   *
   * <p>Two changes met here. This was a JPA Specification built inside the story module — a second
   * definition of "filter conversations", free to drift from the one the conversations table uses
   * (#512 slice 6) — and separately the sanitizer arrived to repair model output (#623). Keeping
   * both means the sentinel decision lives only in {@link InvestigationQuerySanitizer}: this method
   * reads {@code appNameIsNull} rather than re-deriving it, because two places deciding what
   * "unknown" means is exactly the drift #733 was about.
   */
  ConversationFilterParams toFilter(InvestigationQuerySanitizer.SanitizedQuery sanitized) {
    InvestigationQuery q = sanitized.query();
    boolean appIsNull = sanitized.appNameIsNull();

    return ConversationFilterParams.builder()
        .srcIp(q.getSrcIp())
        .dstIp(q.getDstIp())
        .dstPort(q.getDstPort())
        .protocols(q.getProtocol() == null ? List.of() : List.of(q.getProtocol().toUpperCase()))
        .apps(q.getAppName() == null || appIsNull ? List.of() : List.of(q.getAppName()))
        .appIsNull(appIsNull ? Boolean.TRUE : null)
        .categories(q.getCategory() == null ? List.of() : List.of(q.getCategory()))
        .hasRisks(Boolean.TRUE.equals(q.getHasRisks()) ? Boolean.TRUE : null)
        .hasTlsAnomaly(Boolean.TRUE.equals(q.getHasTlsAnomaly()) ? Boolean.TRUE : null)
        .riskTypes(q.getRiskType() == null ? List.of() : List.of(q.getRiskType()))
        // The sanitizer has already dropped bounds the model was likely to have filled with an
        // aggregate total, so they pass straight through here.
        .minBytes(q.getMinBytes())
        .maxBytes(q.getMaxBytes())
        .minFlows(q.getMinFlows())
        .sortBy("totalBytes")
        .sortDir("desc")
        .build();
  }

  private ConversationEvidence toEvidence(ConversationFacts f) {
    var flow = f.flow();
    var tls = f.tls();
    var findings = f.findings();

    return ConversationEvidence.builder()
        .srcIp(flow.srcIp())
        .srcPort(flow.srcPort())
        .dstIp(flow.dstIp())
        .dstPort(flow.dstPort())
        .protocol(flow.protocol())
        .appName(findings.appName())
        .category(findings.category())
        .hostname(tls.hostname())
        .totalBytes(flow.totalBytes())
        .packetCount(flow.packetCount())
        .startTime(flow.startTime() != null ? flow.startTime().toString() : null)
        .endTime(flow.endTime() != null ? flow.endTime().toString() : null)
        .flowRisks(findings.flowRisks() != null ? findings.flowRisks() : List.of())
        .tlsIssuer(tls.tlsIssuer())
        .tlsSubject(tls.tlsSubject())
        .ja3Client(tls.ja3Client())
        .build();
  }
}
