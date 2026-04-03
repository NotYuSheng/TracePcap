package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.AnalysisSummaryResponse;
import com.tracepcap.analysis.dto.ConversationDetailResponse;
import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.dto.PacketResponse;
import com.tracepcap.analysis.dto.ProtocolStatsResponse;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.entity.PacketEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.StorageService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.io.File;
import java.time.Duration;
import java.util.*;
import java.util.Arrays;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AnalysisService {

  private static final int PACKET_BATCH_SIZE = 1000;

  @Value("${tracepcap.overview.apps-limited:true}")
  private boolean overviewAppsLimited;

  @Value("${tracepcap.overview.apps-max:100}")
  private int overviewAppsMax;

  // Flush interval: how many conversations to process before flushing the JPA session.
  // Keeps the Hibernate first-level cache from accumulating unbounded saved entities.
  private static final int JPA_FLUSH_INTERVAL = 50;

  @PersistenceContext private EntityManager entityManager;

  private final AnalysisResultRepository analysisResultRepository;
  private final ConversationRepository conversationRepository;
  private final PacketRepository packetRepository;
  private final HostClassificationRepository hostClassificationRepository;
  private final IpGeoInfoRepository ipGeoInfoRepository;
  private final FileRepository fileRepository;
  private final StorageService storageService;
  private final PcapParserService pcapParserService;
  private final NdpiService ndpiService;
  private final TsharkEnrichmentService tsharkEnrichmentService;
  private final CustomSignatureService customSignatureService;
  private final DeviceClassifierService deviceClassifierService;
  private final GeoIpService geoIpService;
  private final FileExtractionService fileExtractionService;
  private final AnalysisRecordService analysisRecordService;

  @Transactional
  public void analyzeFile(UUID fileId) {
    log.info("Starting analysis for file: {}", fileId);

    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    // Check if already analyzed or currently in progress
    if (analysisResultRepository.existsByFileId(fileId)) {
      log.info("File {} already analyzed or in progress, skipping", fileId);
      return;
    }

    // Create the IN_PROGRESS record immediately in a separate committed transaction so the
    // frontend can see that analysis has started rather than waiting for the entire job to finish.
    AnalysisResultEntity analysis = analysisRecordService.createInProgress(file);

    try {
      long analysisStart = System.currentTimeMillis();

      // Stage 1: Download
      long t = System.currentTimeMillis();
      File tempFile = File.createTempFile("pcap-", ".pcap");
      try {
      storageService.downloadFileToLocal(file.getMinioPath(), tempFile);
      log.info("[{}] [1/7] Download: {}ms", fileId, System.currentTimeMillis() - t);

      // Stage 2: PCAP parse
      t = System.currentTimeMillis();
      PcapParserService.PcapAnalysisResult parseResult =
          pcapParserService.analyzePcapFile(tempFile);
      log.info("[{}] [2/7] PCAP parse: {}ms  ({} packets, {} conversations)",
          fileId, System.currentTimeMillis() - t,
          parseResult.getPacketCount(), parseResult.getConversations().size());

      // Stage 3: nDPI + tshark enrichment
      t = System.currentTimeMillis();
      if (file.isEnableNdpi()) {
        ndpiService.enrich(tempFile, parseResult.getConversations());
        tsharkEnrichmentService.enrich(tempFile, parseResult.getConversations());
        log.info("[{}] [3/7] nDPI + tshark enrichment: {}ms", fileId, System.currentTimeMillis() - t);
      } else {
        log.info("[{}] [3/7] nDPI + tshark enrichment: skipped", fileId);
      }

      // Stage 4: Signatures, device classification, geo-IP
      t = System.currentTimeMillis();
      customSignatureService.applySignatures(parseResult.getConversations());
      Map<String, String> deviceOverrides =
          customSignatureService.getDeviceTypeOverrides(parseResult.getConversations());
      List<HostClassificationEntity> hostClassifications =
          deviceClassifierService.classify(
              file,
              parseResult.getConversations(),
              parseResult.getHostTtls(),
              parseResult.getHostMacs(),
              deviceOverrides);
      hostClassificationRepository.saveAll(hostClassifications);
      try {
        Set<String> allIps =
            parseResult.getConversations().stream()
                .flatMap(c -> java.util.stream.Stream.of(c.getSrcIp(), c.getDstIp()))
                .collect(Collectors.toSet());
        geoIpService.lookupExternal(allIps);
      } catch (Exception e) {
        log.warn("Geo enrichment pre-warm failed: {}", e.getMessage());
      }
      log.info("[{}] [4/7] Signatures + classification + geo-IP: {}ms", fileId, System.currentTimeMillis() - t);

      // Stage 5: Persist analysis result
      t = System.currentTimeMillis();
      analysis.setPacketCount(parseResult.getPacketCount());
      analysis.setTotalBytes(parseResult.getTotalBytes());
      analysis.setStartTime(parseResult.getStartTime());
      analysis.setEndTime(parseResult.getEndTime());
      if (parseResult.getStartTime() != null && parseResult.getEndTime() != null) {
        Duration duration = Duration.between(parseResult.getStartTime(), parseResult.getEndTime());
        analysis.setDurationMs(duration.toMillis());
      }
      Map<String, Object> protocolStats = new HashMap<>();
      parseResult
          .getProtocolCounts()
          .forEach(
              (protocol, count) -> {
                Map<String, Object> stat = new HashMap<>();
                stat.put("packetCount", count);
                stat.put("bytes", parseResult.getProtocolBytes().getOrDefault(protocol, 0L));
                stat.put("percentage", (count.doubleValue() / parseResult.getPacketCount()) * 100);
                protocolStats.put(protocol, stat);
              });
      analysis.setProtocolStats(protocolStats);
      analysis.setStatus(AnalysisResultEntity.AnalysisStatus.COMPLETED);
      analysisResultRepository.save(analysis);
      log.info("[{}] [5/7] Analysis result saved: {}ms", fileId, System.currentTimeMillis() - t);

      // Stage 6: DB inserts (conversations + packets)
      t = System.currentTimeMillis();
      int convIndex = 0;
      long packetsInserted = 0;
      List<UUID> savedConversationIds = new ArrayList<>();
      for (PcapParserService.ConversationInfo convInfo : parseResult.getConversations()) {
        ConversationEntity conversation =
            ConversationEntity.builder()
                .file(file)
                .srcIp(convInfo.getSrcIp())
                .srcPort(convInfo.getSrcPort())
                .dstIp(convInfo.getDstIp())
                .dstPort(convInfo.getDstPort())
                .protocol(convInfo.getProtocol())
                .appName(convInfo.getAppName())
                .tsharkProtocol(convInfo.getTsharkProtocol())
                .category(convInfo.getCategory())
                .hostname(convInfo.getHostname())
                .ja3Client(convInfo.getJa3Client())
                .ja3Server(convInfo.getJa3Server())
                .tlsIssuer(convInfo.getTlsIssuer())
                .tlsSubject(convInfo.getTlsSubject())
                .tlsNotBefore(convInfo.getTlsNotBefore())
                .tlsNotAfter(convInfo.getTlsNotAfter())
                .flowRisks(toNullableArray(convInfo.getFlowRisks()))
                .customSignatures(toNullableArray(convInfo.getCustomSignatures()))
                .httpUserAgents(toNullableArray(convInfo.getHttpUserAgents()))
                .packetCount(convInfo.getPacketCount())
                .totalBytes(convInfo.getTotalBytes())
                .startTime(convInfo.getStartTime())
                .endTime(convInfo.getEndTime())
                .build();
        ConversationEntity savedConversation = conversationRepository.save(conversation);
        savedConversationIds.add(savedConversation.getId());

        List<PcapParserService.PacketInfo> packetInfos = convInfo.getPackets();
        if (!packetInfos.isEmpty()) {
          for (int i = 0; i < packetInfos.size(); i += PACKET_BATCH_SIZE) {
            int end = Math.min(i + PACKET_BATCH_SIZE, packetInfos.size());
            List<PacketEntity> batch =
                packetInfos.subList(i, end).stream()
                    .map(
                        pktInfo ->
                            PacketEntity.builder()
                                .file(file)
                                .conversation(savedConversation)
                                .packetNumber(pktInfo.getPacketNumber())
                                .timestamp(pktInfo.getTimestamp())
                                .srcIp(pktInfo.getSrcIp())
                                .srcPort(pktInfo.getSrcPort())
                                .dstIp(pktInfo.getDstIp())
                                .dstPort(pktInfo.getDstPort())
                                .protocol(pktInfo.getProtocol())
                                .packetSize(pktInfo.getPacketSize())
                                .info(pktInfo.getInfo())
                                .payload(pktInfo.getPayload())
                                .detectedFileType(pktInfo.getDetectedFileType())
                                .build())
                    .collect(Collectors.toList());
            packetRepository.saveAll(batch);
            packetsInserted += batch.size();
          }
          packetInfos.clear();
        }

        if (++convIndex % JPA_FLUSH_INTERVAL == 0) {
          entityManager.flush();
          entityManager.clear();
          log.info("[{}] [6/7] DB insert progress: {}/{} conversations, {} packets",
              fileId, convIndex, parseResult.getConversations().size(), packetsInserted);
        }
      }
      log.info("[{}] [6/7] DB inserts done: {}ms  ({} conversations, {} packets)",
          fileId, System.currentTimeMillis() - t,
          parseResult.getConversations().size(), packetsInserted);

      // Stage 7: File extraction
      t = System.currentTimeMillis();
      if (file.isEnableFileExtraction()) {
        try {
          fileExtractionService.extractFiles(file, tempFile, savedConversationIds);
          log.info("[{}] [7/7] File extraction: {}ms", fileId, System.currentTimeMillis() - t);
        } catch (Exception e) {
          log.warn("[{}] [7/7] File extraction failed ({}ms): {}", fileId, System.currentTimeMillis() - t, e.getMessage());
        }
      } else {
        log.info("[{}] [7/7] File extraction: skipped", fileId);
      }

      // Update file status
      file.setStatus(com.tracepcap.file.entity.FileEntity.FileStatus.COMPLETED);
      file.setPacketCount(
          parseResult.getPacketCount() != null ? parseResult.getPacketCount().intValue() : null);
      file.setTotalBytes(parseResult.getTotalBytes());
      file.setStartTime(parseResult.getStartTime());
      file.setEndTime(parseResult.getEndTime());
      file.setDuration(analysis.getDurationMs());
      fileRepository.save(file);

      log.info("[{}] Analysis complete: total {}ms", fileId, System.currentTimeMillis() - analysisStart);

      } finally {
        tempFile.delete();
      }

    } catch (Exception e) {
      log.error("Error analyzing file {}: {}", fileId, e.getMessage(), e);

      // Mark analysis as FAILED in a separate committed transaction so the status persists even
      // though the outer transaction is being rolled back.
      try {
        analysisRecordService.markFailed(analysis.getId(), e.getMessage());
      } catch (Exception markEx) {
        log.error("Failed to mark analysis {} as FAILED: {}", analysis.getId(), markEx.getMessage());
      }

      throw new RuntimeException("Failed to analyze file", e);
    }
  }

  @Transactional(readOnly = true)
  public AnalysisSummaryResponse getAnalysisSummary(UUID fileId) {
    AnalysisResultEntity analysis =
        analysisResultRepository
            .findByFileId(fileId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Analysis not found for file: " + fileId));

    FileEntity file = analysis.getFile();

    // Convert time to Unix timestamps (milliseconds)
    Long startTimeMs =
        analysis.getStartTime() != null
            ? analysis.getStartTime().toInstant(java.time.ZoneOffset.UTC).toEpochMilli()
            : null;
    Long endTimeMs =
        analysis.getEndTime() != null
            ? analysis.getEndTime().toInstant(java.time.ZoneOffset.UTC).toEpochMilli()
            : null;
    Long uploadTimeMs =
        file.getUploadedAt() != null
            ? file.getUploadedAt().toInstant(java.time.ZoneOffset.UTC).toEpochMilli()
            : null;

    // Build protocol distribution
    List<AnalysisSummaryResponse.ProtocolStat> protocolDistribution = new ArrayList<>();
    if (analysis.getProtocolStats() != null) {
      analysis
          .getProtocolStats()
          .forEach(
              (protocol, statsObj) -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> stats = (Map<String, Object>) statsObj;
                protocolDistribution.add(
                    AnalysisSummaryResponse.ProtocolStat.builder()
                        .protocol(protocol)
                        .count(((Number) stats.get("packetCount")).longValue())
                        .bytes(
                            stats.get("bytes") != null
                                ? ((Number) stats.get("bytes")).longValue()
                                : 0L)
                        .percentage((Double) stats.get("percentage"))
                        .build());
              });
    }

    // Get top conversations
    List<ConversationEntity> conversations = conversationRepository.findByFileId(fileId);
    Map<String, long[]> appStatsMap = new java.util.TreeMap<>();
    conversations.stream()
        .filter(conv -> conv.getAppName() != null && !conv.getAppName().isBlank())
        .forEach(
            conv -> {
              long[] stats =
                  appStatsMap.computeIfAbsent(conv.getAppName(), k -> new long[] {0L, 0L});
              stats[0] += conv.getPacketCount() != null ? conv.getPacketCount() : 0L;
              stats[1] += conv.getTotalBytes() != null ? conv.getTotalBytes() : 0L;
            });
    List<AnalysisSummaryResponse.DetectedApplication> allApps =
        appStatsMap.entrySet().stream()
            .map(
                e ->
                    AnalysisSummaryResponse.DetectedApplication.builder()
                        .name(e.getKey())
                        .packetCount(e.getValue()[0])
                        .bytes(e.getValue()[1])
                        .build())
            .collect(Collectors.toList());
    boolean appsTruncated = overviewAppsLimited && allApps.size() > overviewAppsMax;
    List<AnalysisSummaryResponse.DetectedApplication> detectedApplications =
        appsTruncated ? allApps.subList(0, overviewAppsMax) : allApps;

    List<String> detectedL7Protocols =
        conversations.stream()
            .map(ConversationEntity::getTsharkProtocol)
            .filter(p -> p != null && !p.isBlank())
            .distinct()
            .sorted()
            .collect(Collectors.toList());

    // Aggregate category distribution
    class CategoryAggregate {
      long packetCount = 0L;
      long totalBytes = 0L;
    }
    Map<String, CategoryAggregate> catStatsMap = new java.util.TreeMap<>();
    conversations.stream()
        .filter(conv -> conv.getCategory() != null && !conv.getCategory().isBlank())
        .forEach(
            conv -> {
              CategoryAggregate agg =
                  catStatsMap.computeIfAbsent(conv.getCategory(), k -> new CategoryAggregate());
              agg.packetCount += conv.getPacketCount() != null ? conv.getPacketCount() : 0L;
              agg.totalBytes += conv.getTotalBytes() != null ? conv.getTotalBytes() : 0L;
            });
    long totalCatPackets = catStatsMap.values().stream().mapToLong(a -> a.packetCount).sum();
    List<AnalysisSummaryResponse.CategoryStat> categoryDistribution =
        catStatsMap.entrySet().stream()
            .map(
                e ->
                    AnalysisSummaryResponse.CategoryStat.builder()
                        .category(e.getKey())
                        .count(e.getValue().packetCount)
                        .bytes(e.getValue().totalBytes)
                        .percentage(
                            totalCatPackets > 0
                                ? (e.getValue().packetCount * 100.0 / totalCatPackets)
                                : 0.0)
                        .build())
            .sorted(
                java.util.Comparator.comparingLong(AnalysisSummaryResponse.CategoryStat::getCount)
                    .reversed())
            .collect(Collectors.toList());

    long securityAlertCount =
        conversations.stream()
            .filter(
                conv ->
                    (conv.getFlowRisks() != null && conv.getFlowRisks().length > 0)
                        || (conv.getCustomSignatures() != null
                            && conv.getCustomSignatures().length > 0))
            .count();

    List<String> triggeredCustomRules =
        conversations.stream()
            .filter(
                conv -> conv.getCustomSignatures() != null && conv.getCustomSignatures().length > 0)
            .flatMap(conv -> Arrays.stream(conv.getCustomSignatures()))
            .distinct()
            .sorted()
            .collect(Collectors.toList());

    List<AnalysisSummaryResponse.ConversationSummary> topConversations =
        conversations.stream()
            .sorted((a, b) -> Long.compare(b.getTotalBytes(), a.getTotalBytes()))
            .limit(10)
            .map(
                conv ->
                    AnalysisSummaryResponse.ConversationSummary.builder()
                        .id(conv.getId().toString())
                        .srcIp(conv.getSrcIp())
                        .srcPort(conv.getSrcPort())
                        .dstIp(conv.getDstIp())
                        .dstPort(conv.getDstPort())
                        .protocol(conv.getProtocol())
                        .appName(conv.getAppName())
                        .hostname(conv.getHostname())
                        .startTime(
                            conv.getStartTime() != null
                                ? conv.getStartTime()
                                    .toInstant(java.time.ZoneOffset.UTC)
                                    .toEpochMilli()
                                : null)
                        .endTime(
                            conv.getEndTime() != null
                                ? conv.getEndTime()
                                    .toInstant(java.time.ZoneOffset.UTC)
                                    .toEpochMilli()
                                : null)
                        .packetCount(conv.getPacketCount())
                        .totalBytes(conv.getTotalBytes())
                        .flowRisks(
                            conv.getFlowRisks() != null
                                ? Arrays.asList(conv.getFlowRisks())
                                : List.of())
                        .customSignatures(
                            conv.getCustomSignatures() != null
                                ? Arrays.asList(conv.getCustomSignatures())
                                : List.of())
                        .build())
            .collect(Collectors.toList());

    // Get unique hosts
    Set<String> uniqueIps = new HashSet<>();
    List<AnalysisSummaryResponse.UniqueHost> uniqueHosts = new ArrayList<>();
    conversations.forEach(
        conv -> {
          if (uniqueIps.add(conv.getSrcIp())) {
            uniqueHosts.add(
                AnalysisSummaryResponse.UniqueHost.builder()
                    .ip(conv.getSrcIp())
                    .port(conv.getSrcPort())
                    .build());
          }
          if (uniqueIps.add(conv.getDstIp())) {
            uniqueHosts.add(
                AnalysisSummaryResponse.UniqueHost.builder()
                    .ip(conv.getDstIp())
                    .port(conv.getDstPort())
                    .build());
          }
        });

    return AnalysisSummaryResponse.builder()
        .analysisId(analysis.getId())
        .fileId(file.getId().toString())
        .fileName(file.getFileName())
        .fileSize(file.getFileSize())
        .uploadTime(uploadTimeMs)
        .totalPackets(analysis.getPacketCount())
        .timeRange(
            startTimeMs != null && endTimeMs != null ? List.of(startTimeMs, endTimeMs) : List.of())
        .protocolDistribution(protocolDistribution)
        .topConversations(topConversations)
        .securityAlertCount(securityAlertCount)
        .triggeredCustomRules(triggeredCustomRules)
        .uniqueHosts(uniqueHosts)
        .detectedApplications(detectedApplications)
        .detectedApplicationsTruncated(appsTruncated)
        .detectedL7Protocols(detectedL7Protocols)
        .categoryDistribution(categoryDistribution)
        // Legacy fields
        .startTime(analysis.getStartTime())
        .endTime(analysis.getEndTime())
        .durationMs(analysis.getDurationMs())
        .status(analysis.getStatus().name())
        .errorMessage(analysis.getErrorMessage())
        .analyzedAt(analysis.getCreatedAt())
        .build();
  }

  @Transactional(readOnly = true)
  public ProtocolStatsResponse getProtocolStats(UUID fileId) {
    AnalysisResultEntity analysis =
        analysisResultRepository
            .findByFileId(fileId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Analysis not found for file: " + fileId));

    Map<String, ProtocolStatsResponse.ProtocolStat> protocols = new HashMap<>();

    if (analysis.getProtocolStats() != null) {
      analysis
          .getProtocolStats()
          .forEach(
              (protocol, statsObj) -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> stats = (Map<String, Object>) statsObj;

                protocols.put(
                    protocol,
                    ProtocolStatsResponse.ProtocolStat.builder()
                        .packetCount(((Number) stats.get("packetCount")).longValue())
                        .bytes(
                            stats.get("bytes") != null
                                ? ((Number) stats.get("bytes")).longValue()
                                : 0L)
                        .percentage((Double) stats.get("percentage"))
                        .build());
              });
    }

    return ProtocolStatsResponse.builder().fileId(fileId).protocols(protocols).build();
  }

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

  /** Also used by the CSV export — returns ALL matching rows without pagination. */
  @Transactional(readOnly = true)
  public List<ConversationResponse> getConversationsForExport(
      UUID fileId, ConversationFilterParams params) {

    Sort sort = buildSort(params);
    Specification<ConversationEntity> spec = ConversationRepository.buildSpec(fileId, params);
    List<ConversationEntity> entities = conversationRepository.findAll(spec, sort);

    return mapConversationsWithFileTypes(entities);
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

  private ConversationResponse toConversationResponse(
      ConversationEntity conv, Map<UUID, List<String>> fileTypeMap) {
    return toConversationResponse(conv, fileTypeMap, Map.of());
  }

  private ConversationResponse toConversationResponse(ConversationEntity conv) {
    return toConversationResponse(conv, Map.of(), Map.of());
  }

  private static ConversationResponse.GeoInfo toGeoInfo(GeoIpService.GeoResult result) {
    if (result == null || result.countryCode() == null) return null;
    return ConversationResponse.GeoInfo.builder()
        .country(result.country())
        .countryCode(result.countryCode())
        .asn(result.asn())
        .org(result.org())
        .build();
  }

  @Transactional(readOnly = true)
  public List<ConversationResponse> getSecurityAlerts(UUID fileId) {
    List<ConversationEntity> conversations = conversationRepository.findByFileIdWithRisks(fileId);

    return conversations.stream()
        .map(
            conv -> {
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
                  .httpUserAgents(toList(conv.getHttpUserAgents()))
                  .packetCount(conv.getPacketCount())
                  .totalBytes(conv.getTotalBytes())
                  .startTime(conv.getStartTime())
                  .endTime(conv.getEndTime())
                  .durationMs(duration.toMillis())
                  .build();
            })
        .collect(Collectors.toList());
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

  /**
   * Get analysis result entity by file ID (for status checking) Returns null if analysis doesn't
   * exist yet
   */
  @Transactional(readOnly = true)
  public AnalysisResultEntity getAnalysisResultByFileId(UUID fileId) {
    return analysisResultRepository.findByFileId(fileId).orElse(null);
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

  /** Converts a nullable String array to an immutable list; returns empty list for null. */
  private static List<String> toList(String[] arr) {
    return arr != null ? Arrays.asList(arr) : List.of();
  }

  /**
   * Converts a list to a String array for PostgreSQL array storage. Returns null for empty lists so
   * the DB column stores NULL rather than an empty array.
   */
  private static String[] toNullableArray(List<String> list) {
    return (list == null || list.isEmpty()) ? null : list.toArray(new String[0]);
  }
}
