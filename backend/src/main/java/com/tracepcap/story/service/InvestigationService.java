package com.tracepcap.story.service;

import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.story.dto.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class InvestigationService {

  private final ConversationRepository conversationRepository;

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

        Specification<ConversationEntity> spec = buildSpec(fileId, query);
        var page =
            conversationRepository.findAll(
                spec, PageRequest.of(0, 10, Sort.by("totalBytes").descending()));

        List<ConversationEvidence> evidence =
            page.getContent().stream().map(this::toEvidence).collect(Collectors.toList());

        steps.add(
            InvestigationStep.builder()
                .query(query)
                .hypothesis(linked)
                .conversations(evidence)
                .conversationCount(page.getTotalElements())
                .build());

        log.info(
            "Query '{}' ({}): {} total matches, returning {}",
            query.getId(),
            query.getLabel(),
            page.getTotalElements(),
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

  private Specification<ConversationEntity> buildSpec(UUID fileId, InvestigationQuery q) {
    return (root, query, cb) -> {
      List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();

      predicates.add(cb.equal(root.get("file").get("id"), fileId));

      if (q.getSrcIp() != null) predicates.add(cb.equal(root.get("srcIp"), q.getSrcIp()));
      if (q.getDstIp() != null) predicates.add(cb.equal(root.get("dstIp"), q.getDstIp()));
      if (q.getDstPort() != null) predicates.add(cb.equal(root.get("dstPort"), q.getDstPort()));
      if (q.getProtocol() != null)
        predicates.add(cb.equal(cb.upper(root.get("protocol")), q.getProtocol().toUpperCase()));
      if (q.getAppName() != null) {
        // Sentinel values the LLM uses to mean "unknown/null app" — map to IS NULL
        if (q.getAppName().equalsIgnoreCase("UNKNOWN_APP")
            || q.getAppName().equalsIgnoreCase("unknown")
            || q.getAppName().equalsIgnoreCase("null")
            || q.getAppName().isBlank()) {
          predicates.add(cb.isNull(root.get("appName")));
        } else {
          predicates.add(cb.equal(root.get("appName"), q.getAppName()));
        }
      }
      if (q.getCategory() != null) predicates.add(cb.equal(root.get("category"), q.getCategory()));
      // minBytes/maxBytes are per-conversation filters. Drop them when srcIp or riskType is also
      // set — in those cases the LLM tends to pass the aggregate total which would match nothing.
      boolean byteFilterSafe = q.getSrcIp() == null && q.getRiskType() == null;
      if (q.getMinBytes() != null && byteFilterSafe)
        predicates.add(cb.greaterThanOrEqualTo(root.get("totalBytes"), q.getMinBytes()));
      if (q.getMaxBytes() != null && byteFilterSafe)
        predicates.add(cb.lessThanOrEqualTo(root.get("totalBytes"), q.getMaxBytes()));

      if (Boolean.TRUE.equals(q.getHasRisks())) {
        predicates.add(
            cb.greaterThan(cb.function("cardinality", Integer.class, root.get("flowRisks")), 0));
      }

      if (Boolean.TRUE.equals(q.getHasTlsAnomaly())) {
        predicates.add(cb.isNotNull(root.get("tlsIssuer")));
      }

      if (q.getRiskType() != null) {
        // Match exact element in the PostgreSQL array text representation: {a,b,c}
        // An element can appear as: {riskType,  {riskType}  ,riskType,  ,riskType}
        String rt = q.getRiskType();
        predicates.add(
            cb.or(
                cb.like(root.get("flowRisks").as(String.class), "{" + rt + ",%"),
                cb.like(root.get("flowRisks").as(String.class), "%," + rt + ",%"),
                cb.like(root.get("flowRisks").as(String.class), "%," + rt + "}"),
                cb.equal(root.get("flowRisks").as(String.class), "{" + rt + "}")));
      }

      if (q.getMinFlows() != null) {
        // Subquery: src IPs with at least minFlows conversations in this file
        var subquery = query.subquery(String.class);
        var subRoot = subquery.from(ConversationEntity.class);
        subquery
            .select(subRoot.get("srcIp"))
            .where(cb.equal(subRoot.get("file").get("id"), fileId))
            .groupBy(subRoot.get("srcIp"))
            .having(cb.greaterThanOrEqualTo(cb.count(subRoot), (long) q.getMinFlows()));
        predicates.add(root.get("srcIp").in(subquery));
      }

      return cb.and(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
    };
  }

  private ConversationEvidence toEvidence(ConversationEntity e) {
    List<String> risks = e.getFlowRisks() != null ? Arrays.asList(e.getFlowRisks()) : List.of();

    return ConversationEvidence.builder()
        .srcIp(e.getSrcIp())
        .srcPort(e.getSrcPort())
        .dstIp(e.getDstIp())
        .dstPort(e.getDstPort())
        .protocol(e.getProtocol())
        .appName(e.getAppName())
        .category(e.getCategory())
        .hostname(e.getHostname())
        .totalBytes(e.getTotalBytes())
        .packetCount(e.getPacketCount())
        .startTime(e.getStartTime() != null ? e.getStartTime().toString() : null)
        .endTime(e.getEndTime() != null ? e.getEndTime().toString() : null)
        .flowRisks(risks)
        .tlsIssuer(e.getTlsIssuer())
        .tlsSubject(e.getTlsSubject())
        .ja3Client(e.getJa3Client())
        .build();
  }
}
