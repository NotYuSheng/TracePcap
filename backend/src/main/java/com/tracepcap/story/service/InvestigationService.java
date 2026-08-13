package com.tracepcap.story.service;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.story.dto.*;
import java.util.ArrayList;
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

  public List<InvestigationStep> executeQueries(
      UUID fileId, List<InvestigationQuery> queries, List<Hypothesis> hypotheses) {

    List<InvestigationStep> steps = new ArrayList<>();
    List<InvestigationQuery> capped = queries.stream().limit(5).collect(Collectors.toList());

    for (InvestigationQuery query : capped) {
      if (isCatchAll(query)) {
        log.warn("Skipping catch-all investigation query: {}", query.getId());
        continue;
      }

      try {
        Hypothesis linked =
            hypotheses.stream()
                .filter(h -> query.getId().equals(h.getQueryRef()))
                .findFirst()
                .orElse(null);

        var page = conversationLookup.conversationPage(fileId, 1, 10, toFilter(query));

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

  private boolean isCatchAll(InvestigationQuery q) {
    return q.getSrcIp() == null
        && q.getDstIp() == null
        && q.getDstPort() == null
        && q.getProtocol() == null
        && q.getAppName() == null
        && q.getCategory() == null
        && q.getHasRisks() == null
        && q.getHasTlsAnomaly() == null
        && q.getRiskType() == null
        && q.getMinBytes() == null
        && q.getMaxBytes() == null
        && q.getMinFlows() == null;
  }

  /**
   * Maps an LLM-produced query onto the shared conversation filter (#512 slice 6).
   *
   * <p>This used to be a JPA Specification built here, over {@code ConversationEntity} — a second
   * definition of "filter conversations" living in the story module, free to drift from the one the
   * conversations table uses. The filtering now happens behind the port, in SQL, which also keeps
   * the aggregation off the heap.
   */
  // Package-private: the mapping is where this service's LLM-facing semantics live.
  ConversationFilterParams toFilter(InvestigationQuery q) {
    boolean appUnknown = isUnknownAppSentinel(q.getAppName());
    // minBytes/maxBytes are per-conversation bounds. Dropped when srcIp or riskType is also set:
    // in those cases the model tends to pass an aggregate total, which matches nothing.
    boolean byteFilterSafe = q.getSrcIp() == null && q.getRiskType() == null;

    return ConversationFilterParams.builder()
        .srcIp(q.getSrcIp())
        .dstIp(q.getDstIp())
        .dstPort(q.getDstPort())
        .protocols(q.getProtocol() == null ? List.of() : List.of(q.getProtocol().toUpperCase()))
        .apps(q.getAppName() == null || appUnknown ? List.of() : List.of(q.getAppName()))
        .appIsNull(appUnknown ? Boolean.TRUE : null)
        .categories(q.getCategory() == null ? List.of() : List.of(q.getCategory()))
        .hasRisks(Boolean.TRUE.equals(q.getHasRisks()) ? Boolean.TRUE : null)
        .hasTlsAnomaly(Boolean.TRUE.equals(q.getHasTlsAnomaly()) ? Boolean.TRUE : null)
        .riskTypes(q.getRiskType() == null ? List.of() : List.of(q.getRiskType()))
        .minBytes(byteFilterSafe ? q.getMinBytes() : null)
        .maxBytes(byteFilterSafe ? q.getMaxBytes() : null)
        .minFlows(q.getMinFlows())
        .sortBy("totalBytes")
        .sortDir("desc")
        .build();
  }

  /** Sentinels the model uses to mean "no identified application". */
  private static boolean isUnknownAppSentinel(String appName) {
    if (appName == null) return false;
    return appName.isBlank()
        || appName.equalsIgnoreCase("UNKNOWN_APP")
        || appName.equalsIgnoreCase("unknown")
        || appName.equalsIgnoreCase("null");
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
