package com.tracepcap.conversation.service;

import com.tracepcap.analysis.dto.ConversationDetailResponse;
import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.dto.EntityStatsResponse;
import com.tracepcap.analysis.dto.PacketResponse;
import com.tracepcap.analysis.service.GeoIpService;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.Facet;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.analysis.spi.PacketLookup;
import com.tracepcap.analysis.spi.PacketLookup.PacketFacts;
import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.StorageService;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Read-side queries and exports for conversations and their packets.
 *
 * <p>Extracted from {@code AnalysisService} (see #416) so the analysis ingest core stays focused on
 * producing data while this module owns the conversation browse/query/export API. Depends on the
 * core conversation entity/repository and DTOs, never the reverse.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ConversationQueryService {

  private final ConversationLookup conversationLookup;
  private final PacketLookup packetLookup;
  private final GeoOrgLookup geoOrgLookup;

  private final FileRepository fileRepository;
  private final GeoIpService geoIpService;
  private final StorageService storageService;

  private static final java.time.format.DateTimeFormatter PCAP_FILENAME_TS =
      java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss")
          .withZone(java.time.ZoneId.of("Asia/Singapore"));

  /** Number of top peer IPs returned by the entity-stats endpoint (#436). */
  private static final int ENTITY_STATS_TOP_PEERS = 10;

  /**
   * Authoritative aggregate stats for an APPLICATION or PROTOCOL entity across ALL matching
   * conversations in a file (#436). Computed in the DB so the displayed count/packets/bytes/top-peers
   * are always internally consistent, regardless of conversation count, with no client fan-out.
   *
   * @param fileId the file to aggregate over
   * @param appName when non-blank, aggregate conversations whose appName equals this value
   * @param l7Protocol when non-blank (and appName blank), aggregate by L7 protocol (variant-expanded)
   */
  @Transactional(readOnly = true)
  public EntityStatsResponse getEntityStats(UUID fileId, String appName, String l7Protocol) {
    boolean byApp = appName != null && !appName.isBlank();
    boolean byProto = !byApp && l7Protocol != null && !l7Protocol.isBlank();
    if (!byApp && !byProto) {
      throw new IllegalArgumentException("Either appName or l7Protocol must be provided");
    }

    ConversationLookup.EntityStats stats =
        byApp
            ? conversationLookup.statsForApp(fileId, appName.trim(), ENTITY_STATS_TOP_PEERS)
            : conversationLookup.statsForL7Protocol(
                fileId, l7Protocol.trim(), ENTITY_STATS_TOP_PEERS);

    List<EntityStatsResponse.TopPeer> topPeers =
        stats.topPeers().stream()
            .map(p -> EntityStatsResponse.TopPeer.builder().ip(p.ip()).bytes(p.bytes()).build())
            .collect(Collectors.toList());

    return EntityStatsResponse.builder()
        .conversationCount(stats.conversationCount())
        .packetCount(stats.packetCount())
        .totalBytes(stats.totalBytes())
        .topPeers(topPeers)
        .build();
  }

  @Transactional(readOnly = true)
  public PagedResponse<ConversationResponse> getConversations(
      UUID fileId, int page, int pageSize, ConversationFilterParams params) {

    ConversationLookup.ConversationPage dbPage =
        conversationLookup.conversationPage(fileId, page, pageSize, params);

    List<ConversationResponse> content = mapConversationsWithFileTypes(dbPage.content());

    return PagedResponse.of(content, dbPage.totalElements(), page, pageSize);
  }

  /** Returns distinct detected file types found in packets for the given file. */
  @Transactional(readOnly = true)
  public List<String> getDistinctFileTypes(UUID fileId) {
    return conversationLookup.distinctValues(fileId, Facet.FILE_TYPE);
  }

  /**
   * Returns distinct nDPI risk type strings present in at-risk conversations for the given file.
   */
  @Transactional(readOnly = true)
  public List<String> getDistinctRiskTypes(UUID fileId) {
    return conversationLookup.distinctValues(fileId, Facet.RISK_TYPE);
  }

  @Transactional(readOnly = true)
  public List<String> getDistinctCustomSignatures(UUID fileId) {
    return conversationLookup.distinctValues(fileId, Facet.CUSTOM_SIGNATURE);
  }

  /** Returns distinct Suricata IDS alert strings present in this file's conversations. */
  @Transactional(readOnly = true)
  public List<String> getDistinctSuricataAlerts(UUID fileId) {
    return conversationLookup.distinctValues(fileId, Facet.SURICATA_ALERT);
  }

  /** Returns distinct IP addresses (src and dst) seen in this file's conversations. */
  @Transactional(readOnly = true)
  public List<String> getDistinctIps(UUID fileId) {
    return conversationLookup.distinctValues(fileId, Facet.IP);
  }

  /** Returns distinct application names present in this file's conversations. */
  @Transactional(readOnly = true)
  public List<String> getDistinctApps(UUID fileId) {
    return conversationLookup.distinctValues(fileId, Facet.APP_NAME);
  }

  /** Returns distinct L7 (tshark) protocol names present in this file's conversations. */
  @Transactional(readOnly = true)
  public List<String> getDistinctProtocols(UUID fileId) {
    return conversationLookup.distinctValues(fileId, Facet.PROTOCOL);
  }

  /**
   * Returns distinct country codes seen in this file's conversations, as "CC|Country name" strings
   * (e.g. "US|United States"). Only countries with a non-null country code are returned.
   */
  @Transactional(readOnly = true)
  public List<String> getDistinctCountries(UUID fileId) {
    return geoOrgLookup.distinctCountriesInFile(fileId).stream()
        .map(c -> c.code() + "|" + c.name())
        .collect(Collectors.toList());
  }

  /**
   * Returns a descriptive filename for a conversation PCAP export, e.g. {@code
   * tracepcap_capture_04-01-2026_14-30-00.pcap}.
   */
  @Transactional(readOnly = true)
  public String getConversationPcapFilename(UUID conversationId) {
    ConversationFacts conv =
        conversationLookup
            .conversationFactsById(conversationId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Conversation not found: " + conversationId));
    // The conversation carries its fileId; the name lives on the file record, which this service
    // already owns a repository for (see getBulkPcapFilename).
    String base =
        fileRepository
            .findById(conv.fileId())
            .map(FileEntity::getFileName)
            .filter(n -> n != null)
            .map(n -> n.replaceAll("\\.[^.]+$", ""))
            .orElse("capture");
    return "tracepcap_" + base + "_" + PCAP_FILENAME_TS.format(java.time.Instant.now()) + ".pcap";
  }

  /** Returns a descriptive filename for a bulk (filtered) PCAP export. */
  @Transactional(readOnly = true)
  public String getBulkPcapFilename(UUID fileId) {
    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));
    String base =
        file.getFileName() != null ? file.getFileName().replaceAll("\\.[^.]+$", "") : "capture";
    String ts = PCAP_FILENAME_TS.format(java.time.Instant.now());
    return "tracepcap_" + base + "_" + ts + ".pcap";
  }

  /**
   * Exports a single conversation as a PCAP file. Uses the exact frame numbers stored in the
   * database to filter packets, which is reliable regardless of capture format or tunnelling.
   * Streams the result into the given OutputStream.
   */
  @Transactional(readOnly = true)
  public void exportConversationAsPcap(UUID conversationId, java.io.OutputStream out)
      throws IOException {

    ConversationFacts conv =
        conversationLookup
            .conversationFactsById(conversationId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Conversation not found: " + conversationId));

    // minioPath belongs to the file record, not the conversation — ask the file module for it.
    String minioPath =
        fileRepository.findById(conv.fileId()).map(FileEntity::getMinioPath).orElse(null);
    if (minioPath == null) {
      throw new IOException("PCAP file path not found for conversation: " + conversationId);
    }

    List<Long> frameNumbers =
        packetLookup.packetsInConversation(conversationId).stream()
            .map(PacketFacts::packetNumber)
            .collect(Collectors.toList());

    if (frameNumbers.isEmpty()) {
      throw new IOException(
          "No packets found for conversation " + conversationId + "; cannot export PCAP");
    }

    File tempInput = null;
    File tempOutput = null;
    try {
      tempInput = File.createTempFile("pcap-in-", ".pcap");
      tempOutput = File.createTempFile("pcap-out-", ".pcap");

      storageService.downloadFileToLocal(minioPath, tempInput);

      // Use compact set syntax to avoid exceeding OS arg-length limits on large conversations
      String filter =
          "frame.number in {"
              + frameNumbers.stream().map(Object::toString).collect(Collectors.joining(","))
              + "}";

      log.info(
          "Exporting PCAP for conversationId={}, {} frames", conversationId, frameNumbers.size());
      ProcessBuilder pb =
          new ProcessBuilder(
              "tshark",
              "-r",
              tempInput.getAbsolutePath(),
              "-Y",
              filter,
              "-w",
              tempOutput.getAbsolutePath());
      pb.redirectError(ProcessBuilder.Redirect.DISCARD);
      Process proc = pb.start();
      try {
        int exitCode = proc.waitFor();
        if (exitCode != 0) {
          log.error(
              "tshark exited with code {} during PCAP export for conversationId={}",
              exitCode,
              conversationId);
          throw new IOException("tshark failed to filter PCAP (exit code " + exitCode + ")");
        }
      } catch (InterruptedException e) {
        proc.destroyForcibly();
        Thread.currentThread().interrupt();
        throw new IOException("PCAP export interrupted", e);
      }

      try (InputStream is = new FileInputStream(tempOutput)) {
        is.transferTo(out);
      }
    } finally {
      if (tempInput != null && !tempInput.delete()) tempInput.deleteOnExit();
      if (tempOutput != null && !tempOutput.delete()) tempOutput.deleteOnExit();
    }
  }

  /** Also used by the CSV export — returns ALL matching rows without pagination. */
  @Transactional(readOnly = true)
  public List<ConversationResponse> getConversationsForExport(
      UUID fileId, ConversationFilterParams params) {

    return mapConversationsWithFileTypes(conversationLookup.conversationFacts(fileId, params));
  }

  /**
   * Exports filtered conversations as a PCAP file. Downloads the original PCAP from storage,
   * applies a tshark display filter derived from the matched conversations, and streams the result
   * into the given OutputStream.
   *
   * @param fileId the file whose conversations should be exported
   * @param params filter parameters (same as the listing endpoint)
   * @param out the output stream to write the filtered PCAP bytes to
   */
  @Transactional(readOnly = true)
  public void exportConversationsAsPcap(
      UUID fileId, ConversationFilterParams params, java.io.OutputStream out) throws IOException {

    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    List<ConversationResponse> conversations = getConversationsForExport(fileId, params);

    List<UUID> conversationIds =
        conversations.stream()
            .map(ConversationResponse::getConversationId)
            .collect(Collectors.toList());

    List<Long> frameNumbers = packetLookup.frameNumbersInConversations(conversationIds);

    File tempInput = null;
    File tempOutput = null;
    try {
      tempInput = File.createTempFile("pcap-in-", ".pcap");
      tempOutput = File.createTempFile("pcap-out-", ".pcap");

      storageService.downloadFileToLocal(file.getMinioPath(), tempInput);

      // Always apply a display filter so we never accidentally export the full PCAP.
      // When no conversations match, frame.number == 0 produces a valid 0-packet output
      // (real frame numbers start at 1).
      // NOTE: for very large exports the filter string can approach OS ARG_MAX (~2 MB on Linux);
      // this is unlikely in practice for filtered exports but may occur for unfiltered bulk exports
      // of large capture files.
      String filter =
          frameNumbers.isEmpty()
              ? "frame.number == 0"
              : "frame.number in {"
                  + frameNumbers.stream().map(Object::toString).collect(Collectors.joining(","))
                  + "}";
      List<String> cmd =
          new ArrayList<>(
              Arrays.asList(
                  "tshark",
                  "-r",
                  tempInput.getAbsolutePath(),
                  "-Y",
                  filter,
                  "-w",
                  tempOutput.getAbsolutePath()));

      log.info(
          "Exporting PCAP for fileId={} with {} conversations ({} frames)",
          fileId,
          conversations.size(),
          frameNumbers.size());
      ProcessBuilder pb = new ProcessBuilder(cmd);
      pb.redirectError(ProcessBuilder.Redirect.DISCARD);
      Process proc = pb.start();
      try {
        int exitCode = proc.waitFor();
        if (exitCode != 0) {
          log.error("tshark exited with code {} during PCAP export for fileId={}", exitCode, fileId);
          throw new IOException("tshark failed to filter PCAP (exit code " + exitCode + ")");
        }
      } catch (InterruptedException e) {
        proc.destroyForcibly();
        Thread.currentThread().interrupt();
        throw new IOException("PCAP export interrupted", e);
      }

      try (InputStream is = new FileInputStream(tempOutput)) {
        is.transferTo(out);
      }
    } finally {
      if (tempInput != null && !tempInput.delete()) tempInput.deleteOnExit();
      if (tempOutput != null && !tempOutput.delete()) tempOutput.deleteOnExit();
    }
  }

  private List<ConversationResponse> mapConversationsWithFileTypes(
      List<ConversationFacts> conversations) {
    if (conversations.isEmpty()) return List.of();
    List<UUID> convIds = conversations.stream().map(ConversationFacts::id).toList();
    Map<UUID, List<String>> fileTypeMap = buildFileTypeMap(convIds);
    Map<String, GeoIpService.GeoResult> geoMap = buildGeoMap(conversations);
    return conversations.stream()
        .map(c -> toConversationResponse(c, fileTypeMap, geoMap))
        .collect(Collectors.toList());
  }

  private Sort buildSort(ConversationFilterParams params) {
    if (params == null || params.getSortBy() == null || params.getSortBy().isBlank()) {
      return Sort.unsorted();
    }
    // Map frontend field names to entity field names
    String field =
        switch (params.getSortBy()) {
          case "packets" -> "packetCount";
          case "bytes" -> "totalBytes";
          case "duration" -> "startTime"; // duration is computed; proxy with startTime
          default -> params.getSortBy(); // srcIp, dstIp, startTime pass through
        };
    Sort.Direction dir =
        "desc".equalsIgnoreCase(params.getSortDir()) ? Sort.Direction.DESC : Sort.Direction.ASC;
    return Sort.by(dir, field);
  }

  private Map<String, GeoIpService.GeoResult> buildGeoMap(List<ConversationFacts> conversations) {
    Set<String> ips =
        conversations.stream()
            .flatMap(c -> java.util.stream.Stream.of(c.flow().srcIp(), c.flow().dstIp()))
            .filter(ip -> ip != null && !ip.isBlank())
            .collect(Collectors.toSet());
    try {
      return geoIpService.lookupExternal(ips);
    } catch (Exception e) {
      log.warn("Geo lookup failed during response mapping: {}", e.getMessage());
      return java.util.Collections.emptyMap();
    }
  }

  private Map<UUID, List<String>> buildFileTypeMap(List<UUID> ids) {
    if (ids.isEmpty()) return java.util.Collections.emptyMap();
    return packetLookup.detectedFileTypesByConversation(ids);
  }

  private ConversationResponse toConversationResponse(
      ConversationFacts conv,
      Map<UUID, List<String>> fileTypeMap,
      Map<String, GeoIpService.GeoResult> geoMap) {
    Duration duration =
        (conv.flow().startTime() != null && conv.flow().endTime() != null)
            ? Duration.between(conv.flow().startTime(), conv.flow().endTime())
            : Duration.ZERO;
    return ConversationResponse.builder()
        .conversationId(conv.id())
        .srcIp(conv.flow().srcIp())
        .srcPort(conv.flow().srcPort())
        .dstIp(conv.flow().dstIp())
        .dstPort(conv.flow().dstPort())
        .initiatorIp(conv.flow().initiatorIp())
        .initiatorPort(conv.flow().initiatorPort())
        .protocol(conv.flow().protocol())
        .appName(conv.findings().appName())
        .tsharkProtocol(conv.findings().tsharkProtocol())
        .category(conv.findings().category())
        .hostname(conv.tls().hostname())
        .ja3Client(conv.tls().ja3Client())
        .ja3Server(conv.tls().ja3Server())
        .tlsIssuer(conv.tls().tlsIssuer())
        .tlsSubject(conv.tls().tlsSubject())
        .tlsNotBefore(conv.tls().tlsNotBefore())
        .tlsNotAfter(conv.tls().tlsNotAfter())
        .flowRisks(conv.findings().flowRisks())
        .customSignatures(conv.findings().customSignatures())
        .suricataAlerts(conv.findings().suricataAlerts())
        .httpUserAgents(conv.findings().httpUserAgents())
        .detectedFileTypes(fileTypeMap.getOrDefault(conv.id(), List.of()))
        .packetCount(conv.flow().packetCount())
        .totalBytes(conv.flow().totalBytes())
        .startTime(conv.flow().startTime())
        .endTime(conv.flow().endTime())
        .durationMs(duration.toMillis())
        .srcGeo(toGeoInfo(geoMap.get(conv.flow().srcIp())))
        .dstGeo(toGeoInfo(geoMap.get(conv.flow().dstIp())))
        .build();
  }

  private static ConversationResponse.GeoInfo toGeoInfo(GeoIpService.GeoResult result) {
    if (result == null || result.countryCode() == null) return null;
    return ConversationResponse.GeoInfo.builder()
        .country(result.country())
        .countryCode(result.countryCode())
        .asn(result.asn())
        .org(result.org())
        .geoSource(result.geoSource())
        .build();
  }

  @Transactional(readOnly = true)
  public ConversationDetailResponse getConversationDetail(UUID conversationId) {
    ConversationFacts conversation =
        conversationLookup
            .conversationFactsById(conversationId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Conversation not found: " + conversationId));

    List<PacketFacts> packets =
        packetLookup.packetsInConversation(conversationId);

    Duration duration =
        (conversation.flow().startTime() != null && conversation.flow().endTime() != null)
            ? Duration.between(conversation.flow().startTime(), conversation.flow().endTime())
            : Duration.ZERO;

    List<PacketResponse> packetResponses =
        packets.stream().map(this::toPacketResponse).collect(Collectors.toList());

    Set<String> detailIps = new HashSet<>();
    if (conversation.flow().srcIp() != null) detailIps.add(conversation.flow().srcIp());
    if (conversation.flow().dstIp() != null) detailIps.add(conversation.flow().dstIp());
    Map<String, GeoIpService.GeoResult> geoMap = geoIpService.lookupExternal(detailIps);

    return ConversationDetailResponse.builder()
        .conversationId(conversation.id())
        .srcIp(conversation.flow().srcIp())
        .srcPort(conversation.flow().srcPort())
        .dstIp(conversation.flow().dstIp())
        .dstPort(conversation.flow().dstPort())
        .initiatorIp(conversation.flow().initiatorIp())
        .initiatorPort(conversation.flow().initiatorPort())
        .protocol(conversation.flow().protocol())
        .appName(conversation.findings().appName())
        .tsharkProtocol(conversation.findings().tsharkProtocol())
        .category(conversation.findings().category())
        .hostname(conversation.tls().hostname())
        .ja3Client(conversation.tls().ja3Client())
        .ja3Server(conversation.tls().ja3Server())
        .tlsIssuer(conversation.tls().tlsIssuer())
        .tlsSubject(conversation.tls().tlsSubject())
        .tlsNotBefore(conversation.tls().tlsNotBefore())
        .tlsNotAfter(conversation.tls().tlsNotAfter())
        .flowRisks(conversation.findings().flowRisks())
        .customSignatures(conversation.findings().customSignatures())
        .suricataAlerts(conversation.findings().suricataAlerts())
        .httpUserAgents(conversation.findings().httpUserAgents())
        .packetCount(conversation.flow().packetCount())
        .totalBytes(conversation.flow().totalBytes())
        .startTime(conversation.flow().startTime())
        .endTime(conversation.flow().endTime())
        .durationMs(duration.toMillis())
        .srcGeo(toGeoInfo(geoMap.get(conversation.flow().srcIp())))
        .dstGeo(toGeoInfo(geoMap.get(conversation.flow().dstIp())))
        .packets(packetResponses)
        .build();
  }

  private PacketResponse toPacketResponse(PacketFacts p) {
    return PacketResponse.builder()
        .id(p.id())
        .packetNumber(p.packetNumber())
        .timestamp(p.timestamp())
        .srcIp(p.srcIp())
        .srcPort(p.srcPort())
        .dstIp(p.dstIp())
        .dstPort(p.dstPort())
        .protocol(p.protocol())
        .packetSize(p.packetSize())
        .info(p.info())
        .payload(p.payload())
        .detectedFileType(p.detectedFileType())
        .build();
  }

  /** Converts a nullable String array to an immutable list; returns empty list for null. */
}
