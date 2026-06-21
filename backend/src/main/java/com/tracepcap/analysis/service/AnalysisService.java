package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.AnalysisSummaryResponse;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.dto.ProtocolStatsResponse;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.entity.PacketEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.analysis.spi.FileExtractionStage;
import com.tracepcap.analysis.spi.HostClassifier;
import com.tracepcap.analysis.spi.SignatureApplier;
import com.tracepcap.analysis.spi.ServiceLogRoles;
import com.tracepcap.analysis.spi.HostServiceLogExtractor;
import com.tracepcap.analysis.spi.HostServiceLogResult;
import com.tracepcap.analysis.spi.HostServiceSuspicion;
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
  private final FileRepository fileRepository;
  private final StorageService storageService;
  private final PcapParserService pcapParserService;
  private final NdpiService ndpiService;
  private final TsharkEnrichmentService tsharkEnrichmentService;
  private final SuricataService suricataService;
  private final SignatureApplier signatureApplier;
  private final HostClassifier hostClassifier;
  private final HostnameResolverService hostnameResolverService;
  private final List<HostServiceLogExtractor> hostServiceLogExtractors;
  private final GeoIpService geoIpService;
  private final FileExtractionStage fileExtractionStage;
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
        log.info(
            "[{}] [2/7] PCAP parse: {}ms  ({} packets, {} conversations)",
            fileId,
            System.currentTimeMillis() - t,
            parseResult.getPacketCount(),
            parseResult.getConversations().size());

        // Stage 3: nDPI + tshark enrichment
        t = System.currentTimeMillis();
        if (file.isEnableNdpi()) {
          ndpiService.enrich(tempFile, parseResult.getConversations());
          tsharkEnrichmentService.enrich(tempFile, parseResult.getConversations());
        }
        if (file.isEnableSuricata()) {
          suricataService.enrich(tempFile, parseResult.getConversations());
        }
        log.info(
            "[{}] [3/7] Enrichment (nDPI={}, Suricata={}): {}ms",
            fileId,
            file.isEnableNdpi(),
            file.isEnableSuricata(),
            System.currentTimeMillis() - t);

        // Stage 4: Signatures, device classification, geo-IP
        t = System.currentTimeMillis();
        Map<String, String> deviceOverrides =
            signatureApplier.applySignatures(parseResult.getConversations());
        // resolve() degrades gracefully and never throws — it returns a (possibly empty) map.
        Map<String, HostnameResolverService.ResolvedHostname> hostnames =
            hostnameResolverService.resolve(tempFile);
        // Per-host service activity logs (DNS today; web servers etc. later). Each extractor runs
        // one tshark pass, persists its own rows, and reports which hosts serve its role + any
        // suspicious ones. Runs before classification so a host's roles can drive its device type
        // (e.g. a DNS responder → DNS_SERVER). Adding a role needs no change here.
        ServiceLogOutcome serviceLogs = runServiceLogExtractors(file, tempFile);
        List<HostClassificationEntity> hostClassifications =
            hostClassifier.classify(
                file,
                parseResult.getConversations(),
                parseResult.getHostTtls(),
                parseResult.getHostMacs(),
                deviceOverrides,
                hostnames,
                serviceLogs.rolesByIp());
        applyServiceLogSuspicions(hostClassifications, serviceLogs.suspicions());
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
        log.info(
            "[{}] [4/7] Signatures + classification + geo-IP: {}ms",
            fileId,
            System.currentTimeMillis() - t);

        // Stage 5: Persist analysis result
        t = System.currentTimeMillis();
        analysis.setPacketCount(parseResult.getPacketCount());
        analysis.setTotalBytes(parseResult.getTotalBytes());
        analysis.setStartTime(parseResult.getStartTime());
        analysis.setEndTime(parseResult.getEndTime());
        if (parseResult.getStartTime() != null && parseResult.getEndTime() != null) {
          Duration duration =
              Duration.between(parseResult.getStartTime(), parseResult.getEndTime());
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
                  stat.put(
                      "percentage", (count.doubleValue() / parseResult.getPacketCount()) * 100);
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
                  .suricataAlerts(toNullableArray(convInfo.getSuricataAlerts()))
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
            log.info(
                "[{}] [6/7] DB insert progress: {}/{} conversations, {} packets",
                fileId,
                convIndex,
                parseResult.getConversations().size(),
                packetsInserted);
          }
        }
        log.info(
            "[{}] [6/7] DB inserts done: {}ms  ({} conversations, {} packets)",
            fileId,
            System.currentTimeMillis() - t,
            parseResult.getConversations().size(),
            packetsInserted);

        // Stage 7: File extraction
        t = System.currentTimeMillis();
        if (file.isEnableFileExtraction()) {
          try {
            fileExtractionStage.extractFiles(file, tempFile, savedConversationIds);
            log.info("[{}] [7/7] File extraction: {}ms", fileId, System.currentTimeMillis() - t);
          } catch (Exception e) {
            log.warn(
                "[{}] [7/7] File extraction failed ({}ms): {}",
                fileId,
                System.currentTimeMillis() - t,
                e.getMessage());
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

        log.info(
            "[{}] Analysis complete: total {}ms",
            fileId,
            System.currentTimeMillis() - analysisStart);

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
        log.error(
            "Failed to mark analysis {} as FAILED: {}", analysis.getId(), markEx.getMessage());
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
            .map(TsharkEnrichmentService::normalizeL7Protocol)
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
                            && conv.getCustomSignatures().length > 0)
                        || (conv.getSuricataAlerts() != null
                            && conv.getSuricataAlerts().length > 0))
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
                        .suricataAlerts(
                            conv.getSuricataAlerts() != null
                                ? Arrays.asList(conv.getSuricataAlerts())
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
        .totalConversations((long) conversations.size())
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
                  .suricataAlerts(toList(conv.getSuricataAlerts()))
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


  /**
   * Get analysis result entity by file ID (for status checking) Returns null if analysis doesn't
   * exist yet
   */
  @Transactional(readOnly = true)
  public AnalysisResultEntity getAnalysisResultByFileId(UUID fileId) {
    return analysisResultRepository.findByFileId(fileId).orElse(null);
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

  /** Collected output of all service-log extractors: which roles each IP serves, plus suspicions. */
  private record ServiceLogOutcome(
      Map<String, Set<String>> rolesByIp, List<HostServiceSuspicion> suspicions) {}

  /**
   * Runs every registered {@link HostServiceLogExtractor} over the capture. Each extractor persists
   * its own activity-log rows and reports which hosts serve its role + any suspicious ones. Returns
   * the per-IP role map (fed into device classification) and the combined suspicion list. A new
   * service role just adds an extractor bean — nothing here changes.
   */
  private ServiceLogOutcome runServiceLogExtractors(FileEntity file, File pcap) {
    Map<String, Set<String>> rolesByIp = new HashMap<>();
    List<HostServiceSuspicion> suspicions = new ArrayList<>();
    for (HostServiceLogExtractor extractor : hostServiceLogExtractors) {
      try {
        HostServiceLogResult result = extractor.extractAndPersist(file, pcap);
        result
            .roleByServerIp()
            .forEach(
                (ip, role) ->
                    rolesByIp.computeIfAbsent(ip, k -> new LinkedHashSet<>()).add(role));
        suspicions.addAll(result.suspicions());
      } catch (Exception e) {
        log.warn("Host service log extractor '{}' failed: {}", extractor.role(), e.getMessage());
      }
    }
    return new ServiceLogOutcome(rolesByIp, suspicions);
  }

  /**
   * Flags the host classifications named in {@code suspicions}. A new service role adds one {@code
   * if} branch mapping its role to the relevant flag — nothing else changes.
   */
  private void applyServiceLogSuspicions(
      List<HostClassificationEntity> hostClassifications, List<HostServiceSuspicion> suspicions) {
    if (suspicions.isEmpty()) return;
    Map<String, HostClassificationEntity> byIp = new HashMap<>();
    for (HostClassificationEntity h : hostClassifications) {
      byIp.put(h.getIp(), h);
    }
    for (HostServiceSuspicion s : suspicions) {
      HostClassificationEntity host = byIp.get(s.ip());
      if (host == null) continue; // external server with no classification — skip silently
      if (ServiceLogRoles.DNS.equals(s.role())) {
        host.setDnsSuspicious(true);
      }
      // Future roles: else if (HttpEndpointLogExtractor.ROLE.equals(s.role())) host.setWebSuspicious(true);
    }
  }
}
