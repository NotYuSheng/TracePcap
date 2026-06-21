package com.tracepcap.conversation.service;

import com.tracepcap.analysis.dto.ConversationDetailResponse;
import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.dto.PacketResponse;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.PacketEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.analysis.service.GeoIpService;
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

  private final ConversationRepository conversationRepository;
  private final PacketRepository packetRepository;
  private final IpGeoInfoRepository ipGeoInfoRepository;
  private final FileRepository fileRepository;
  private final GeoIpService geoIpService;
  private final StorageService storageService;

  private static final java.time.format.DateTimeFormatter PCAP_FILENAME_TS =
      java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss")
          .withZone(java.time.ZoneId.of("Asia/Singapore"));

  @Transactional(readOnly = true)
  public PagedResponse<ConversationResponse> getConversations(
      UUID fileId, int page, int pageSize, ConversationFilterParams params) {

    Sort sort = buildSort(params);
    PageRequest pageable = PageRequest.of(page - 1, pageSize, sort);
    Specification<ConversationEntity> spec = ConversationRepository.buildSpec(fileId, params);

    Page<ConversationEntity> dbPage = conversationRepository.findAll(spec, pageable);

    List<ConversationResponse> content = mapConversationsWithFileTypes(dbPage.getContent());

    return PagedResponse.of(content, dbPage.getTotalElements(), page, pageSize);
  }

  /** Returns distinct detected file types found in packets for the given file. */
  @Transactional(readOnly = true)
  public List<String> getDistinctFileTypes(UUID fileId) {
    return conversationRepository.findDistinctFileTypesByFileId(fileId);
  }

  /**
   * Returns distinct nDPI risk type strings present in at-risk conversations for the given file.
   */
  @Transactional(readOnly = true)
  public List<String> getDistinctRiskTypes(UUID fileId) {
    return conversationRepository.findDistinctRiskTypesByFileId(fileId);
  }

  @Transactional(readOnly = true)
  public List<String> getDistinctCustomSignatures(UUID fileId) {
    return conversationRepository.findDistinctCustomSignaturesByFileId(fileId);
  }

  /** Returns distinct Suricata IDS alert strings present in this file's conversations. */
  @Transactional(readOnly = true)
  public List<String> getDistinctSuricataAlerts(UUID fileId) {
    return conversationRepository.findDistinctSuricataAlertsByFileId(fileId);
  }

  /**
   * Returns distinct country codes seen in this file's conversations, as "CC|Country name" strings
   * (e.g. "US|United States"). Only countries with a non-null country code are returned.
   */
  @Transactional(readOnly = true)
  public List<String> getDistinctCountries(UUID fileId) {
    return ipGeoInfoRepository.findDistinctCountriesByFileId(fileId).stream()
        .map(row -> row[0] + "|" + row[1])
        .collect(Collectors.toList());
  }

  /**
   * Returns a descriptive filename for a conversation PCAP export, e.g. {@code
   * tracepcap_capture_04-01-2026_14-30-00.pcap}.
   */
  @Transactional(readOnly = true)
  public String getConversationPcapFilename(UUID conversationId) {
    ConversationEntity conv =
        conversationRepository
            .findById(conversationId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Conversation not found: " + conversationId));
    return buildConversationPcapFilename(conv);
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

  private static String buildConversationPcapFilename(ConversationEntity conv) {
    String base =
        conv.getFile() != null && conv.getFile().getFileName() != null
            ? conv.getFile().getFileName().replaceAll("\\.[^.]+$", "")
            : "capture";
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

    ConversationEntity conv =
        conversationRepository
            .findById(conversationId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Conversation not found: " + conversationId));

    List<Long> frameNumbers =
        packetRepository.findByConversationIdOrderByPacketNumberAsc(conversationId).stream()
            .map(PacketEntity::getPacketNumber)
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

      storageService.downloadFileToLocal(conv.getFile().getMinioPath(), tempInput);

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

    Sort sort = buildSort(params);
    Specification<ConversationEntity> spec = ConversationRepository.buildSpec(fileId, params);
    List<ConversationEntity> entities = conversationRepository.findAll(spec, sort);

    return mapConversationsWithFileTypes(entities);
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

    List<Long> frameNumbers =
        conversationIds.isEmpty()
            ? List.of()
            : packetRepository.findPacketNumbersByConversationIds(conversationIds);

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
          log.warn("tshark exited with code {} during PCAP export for fileId={}", exitCode, fileId);
        }
      } catch (InterruptedException e) {
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
      List<ConversationEntity> conversations) {
    if (conversations.isEmpty()) return List.of();
    List<UUID> convIds = conversations.stream().map(ConversationEntity::getId).toList();
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

  private Map<String, GeoIpService.GeoResult> buildGeoMap(List<ConversationEntity> conversations) {
    Set<String> ips =
        conversations.stream()
            .flatMap(c -> java.util.stream.Stream.of(c.getSrcIp(), c.getDstIp()))
            .collect(Collectors.toSet());
    try {
      return geoIpService.lookupExternal(ips);
    } catch (Exception e) {
      log.warn("Geo lookup failed during response mapping: {}", e.getMessage());
      return Map.of();
    }
  }

  private Map<UUID, List<String>> buildFileTypeMap(List<UUID> ids) {
    if (ids.isEmpty()) return Map.of();
    return packetRepository.findFileTypesByConversationIds(ids).stream()
        .collect(
            Collectors.groupingBy(
                row -> (UUID) row[0],
                Collectors.mapping(
                    row -> (String) row[1],
                    Collectors.collectingAndThen(Collectors.toSet(), List::copyOf))));
  }

  private ConversationResponse toConversationResponse(
      ConversationEntity conv,
      Map<UUID, List<String>> fileTypeMap,
      Map<String, GeoIpService.GeoResult> geoMap) {
    Duration duration =
        (conv.getStartTime() != null && conv.getEndTime() != null)
            ? Duration.between(conv.getStartTime(), conv.getEndTime())
            : Duration.ZERO;
    return ConversationResponse.builder()
        .conversationId(conv.getId())
        .srcIp(conv.getSrcIp())
        .srcPort(conv.getSrcPort())
        .dstIp(conv.getDstIp())
        .dstPort(conv.getDstPort())
        .protocol(conv.getProtocol())
        .appName(conv.getAppName())
        .tsharkProtocol(conv.getTsharkProtocol())
        .category(conv.getCategory())
        .hostname(conv.getHostname())
        .ja3Client(conv.getJa3Client())
        .ja3Server(conv.getJa3Server())
        .tlsIssuer(conv.getTlsIssuer())
        .tlsSubject(conv.getTlsSubject())
        .tlsNotBefore(conv.getTlsNotBefore())
        .tlsNotAfter(conv.getTlsNotAfter())
        .flowRisks(toList(conv.getFlowRisks()))
        .customSignatures(toList(conv.getCustomSignatures()))
        .suricataAlerts(toList(conv.getSuricataAlerts()))
        .httpUserAgents(toList(conv.getHttpUserAgents()))
        .detectedFileTypes(fileTypeMap.getOrDefault(conv.getId(), List.of()))
        .packetCount(conv.getPacketCount())
        .totalBytes(conv.getTotalBytes())
        .startTime(conv.getStartTime())
        .endTime(conv.getEndTime())
        .durationMs(duration.toMillis())
        .srcGeo(toGeoInfo(geoMap.get(conv.getSrcIp())))
        .dstGeo(toGeoInfo(geoMap.get(conv.getDstIp())))
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
    ConversationEntity conversation =
        conversationRepository
            .findById(conversationId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Conversation not found: " + conversationId));

    List<PacketEntity> packets =
        packetRepository.findByConversationIdOrderByPacketNumberAsc(conversationId);

    Duration duration =
        (conversation.getStartTime() != null && conversation.getEndTime() != null)
            ? Duration.between(conversation.getStartTime(), conversation.getEndTime())
            : Duration.ZERO;

    List<PacketResponse> packetResponses =
        packets.stream().map(this::toPacketResponse).collect(Collectors.toList());

    Map<String, GeoIpService.GeoResult> geoMap =
        geoIpService.lookupExternal(
            new HashSet<>(List.of(conversation.getSrcIp(), conversation.getDstIp())));

    return ConversationDetailResponse.builder()
        .conversationId(conversation.getId())
        .srcIp(conversation.getSrcIp())
        .srcPort(conversation.getSrcPort())
        .dstIp(conversation.getDstIp())
        .dstPort(conversation.getDstPort())
        .protocol(conversation.getProtocol())
        .appName(conversation.getAppName())
        .tsharkProtocol(conversation.getTsharkProtocol())
        .category(conversation.getCategory())
        .hostname(conversation.getHostname())
        .ja3Client(conversation.getJa3Client())
        .ja3Server(conversation.getJa3Server())
        .tlsIssuer(conversation.getTlsIssuer())
        .tlsSubject(conversation.getTlsSubject())
        .tlsNotBefore(conversation.getTlsNotBefore())
        .tlsNotAfter(conversation.getTlsNotAfter())
        .flowRisks(toList(conversation.getFlowRisks()))
        .customSignatures(toList(conversation.getCustomSignatures()))
        .suricataAlerts(toList(conversation.getSuricataAlerts()))
        .httpUserAgents(toList(conversation.getHttpUserAgents()))
        .packetCount(conversation.getPacketCount())
        .totalBytes(conversation.getTotalBytes())
        .startTime(conversation.getStartTime())
        .endTime(conversation.getEndTime())
        .durationMs(duration.toMillis())
        .srcGeo(toGeoInfo(geoMap.get(conversation.getSrcIp())))
        .dstGeo(toGeoInfo(geoMap.get(conversation.getDstIp())))
        .packets(packetResponses)
        .build();
  }

  private PacketResponse toPacketResponse(PacketEntity p) {
    return PacketResponse.builder()
        .id(p.getId())
        .packetNumber(p.getPacketNumber())
        .timestamp(p.getTimestamp())
        .srcIp(p.getSrcIp())
        .srcPort(p.getSrcPort())
        .dstIp(p.getDstIp())
        .dstPort(p.getDstPort())
        .protocol(p.getProtocol())
        .packetSize(p.getPacketSize())
        .info(p.getInfo())
        .payload(p.getPayload())
        .detectedFileType(p.getDetectedFileType())
        .build();
  }

  /** Converts a nullable String array to an immutable list; returns empty list for null. */
  private static List<String> toList(String[] arr) {
    return arr != null ? Arrays.asList(arr) : List.of();
  }
}
