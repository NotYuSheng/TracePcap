package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.spi.ConversationLookup;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;

/** Serves {@link ConversationLookup} from the analysis module's own repository. */
@Component
@RequiredArgsConstructor
public class ConversationLookupAdapter implements ConversationLookup {

  private final ConversationRepository repository;

  @Override
  public List<ConversationFacts> conversationFacts(UUID fileId) {
    return repository.findByFileId(fileId).stream().map(ConversationLookupAdapter::toFacts).toList();
  }

  @Override
  public List<ConversationFacts> conversationFacts(UUID fileId, ConversationFilterParams filter) {
    // The Specification stays on this side of the seam: returning it would put ConversationEntity
    // in the caller's signature, which is how the filtered paths bypassed the port before.
    List<ConversationEntity> rows =
        filter == null
            ? repository.findByFileId(fileId)
            : repository.findAll(ConversationRepository.buildSpec(fileId, filter));
    return rows.stream().map(ConversationLookupAdapter::toFacts).toList();
  }

  @Override
  public ConversationPage conversationPage(
      UUID fileId, int page, int pageSize, ConversationFilterParams filter) {
    Page<ConversationEntity> dbPage =
        repository.findAll(
            ConversationRepository.buildSpec(fileId, filter),
            PageRequest.of(page - 1, pageSize, sortOf(filter)));
    return new ConversationPage(
        dbPage.getContent().stream().map(ConversationLookupAdapter::toFacts).toList(),
        dbPage.getTotalElements());
  }

  /**
   * Maps the API's sort field onto a column. This lives here because it is schema knowledge: "bytes"
   * is what the API calls it, {@code totalBytes} is what the entity calls it, and a feature module
   * knowing the second is reaching through the seam with a string.
   */
  private static Sort sortOf(ConversationFilterParams params) {
    if (params == null || params.getSortBy() == null || params.getSortBy().isBlank()) {
      return Sort.unsorted();
    }
    String field =
        switch (params.getSortBy()) {
          case "packets" -> "packetCount";
          case "bytes" -> "totalBytes";
          // Duration is computed, not stored; startTime is the closest stored proxy.
          case "duration" -> "startTime";
          case "srcIp", "dstIp", "startTime", "endTime", "protocol" -> params.getSortBy();
          // Unknown field: unsorted beats an InvalidDataAccessApiUsageException from a bad property.
          default -> null;
        };
    if (field == null) return Sort.unsorted();
    Sort.Direction dir =
        "desc".equalsIgnoreCase(params.getSortDir()) ? Sort.Direction.DESC : Sort.Direction.ASC;
    return Sort.by(dir, field);
  }

  @Override
  public Optional<ConversationFacts> conversationFactsById(UUID conversationId) {
    return repository.findById(conversationId).map(ConversationLookupAdapter::toFacts);
  }

  @Override
  public List<ConversationFacts> conversationFactsForIp(UUID fileId, String ip) {
    // The repository query carries ORDER BY packetCount DESC, which the port promises. Kept here
    // rather than re-sorted: the DB already did it.
    return repository.findByFileIdAndIp(fileId, ip).stream()
        .map(ConversationLookupAdapter::toFacts)
        .toList();
  }

  @Override
  public List<ConversationFacts> conversationFactsByIds(Collection<UUID> conversationIds) {
    if (conversationIds == null || conversationIds.isEmpty()) return List.of();
    return repository.findAllById(conversationIds).stream()
        .map(ConversationLookupAdapter::toFacts)
        .toList();
  }

  @Override
  public List<String> distinctValues(UUID fileId, Facet facet) {
    List<String> raw =
        switch (facet) {
          case SURICATA_ALERT -> repository.findDistinctSuricataAlertsByFileId(fileId);
          case CUSTOM_SIGNATURE -> repository.findDistinctCustomSignaturesByFileId(fileId);
          case RISK_TYPE -> repository.findDistinctRiskTypesByFileId(fileId);
          case FILE_TYPE -> repository.findDistinctFileTypesByFileId(fileId);
          case APP_NAME -> repository.findDistinctAppNamesByFileId(fileId);
          case IP -> repository.findDistinctIpsByFileId(fileId);
          case PROTOCOL -> repository.findDistinctProtocolsByFileId(fileId);
        };
    // The port promises no nulls or blanks; the native DISTINCT queries can yield both.
    return raw.stream().filter(v -> v != null && !v.isBlank()).toList();
  }

  private static ConversationFacts toFacts(ConversationEntity e) {
    return new ConversationFacts(
        e.getId(),
        e.getFile() == null ? null : e.getFile().getId(),
        new FlowIdentity(
            e.getSrcIp(),
            e.getSrcPort(),
            e.getDstIp(),
            e.getDstPort(),
            e.getProtocol(),
            e.getPacketCount() == null ? 0 : e.getPacketCount(),
            e.getTotalBytes() == null ? 0 : e.getTotalBytes(),
            e.getStartTime(),
            e.getEndTime()),
        new TlsFacts(
            e.getHostname(),
            e.getTlsIssuer(),
            e.getTlsSubject(),
            e.getTlsNotBefore(),
            e.getTlsNotAfter(),
            e.getJa3Client(),
            e.getJa3Server()),
        new Findings(
            e.getAppName(),
            e.getTsharkProtocol(),
            e.getCategory(),
            immutable(e.getFlowRisks()),
            immutable(e.getSuricataAlerts()),
            immutable(e.getCustomSignatures()),
            immutable(e.getHttpUserAgents())));
  }

  /**
   * Copies a Postgres {@code text[]} column into an immutable list (empty when the column is null).
   * The copy is the point: handing back {@code Arrays.asList(array)} would write through to the
   * entity's own array, letting any consumer mutate the fact base.
   */
  private static List<String> immutable(String[] values) {
    if (values == null || values.length == 0) return List.of();
    return Arrays.stream(values).filter(v -> v != null).toList();
  }
}
