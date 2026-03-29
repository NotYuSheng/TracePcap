package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.AnalysisSummaryResponse;
import com.tracepcap.analysis.dto.ConversationDetailResponse;
import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.dto.PacketResponse;
import com.tracepcap.analysis.dto.ProtocolStatsResponse;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.PacketEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.StorageService;
import java.io.File;
import java.time.Duration;
import java.util.*;
import java.util.Arrays;
import java.util.stream.Collectors;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
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

  @PersistenceContext
  private EntityManager entityManager;

  private final AnalysisResultRepository analysisResultRepository;
  private final ConversationRepository conversationRepository;
  private final PacketRepository packetRepository;
  private final FileRepository fileRepository;
  private final StorageService storageService;
  private final PcapParserService pcapParserService;
  private final NdpiService ndpiService;
  private final CustomSignatureService customSignatureService;

  @Transactional
  public void reanalyzeFile(UUID fileId) {
    log.info("Forcing re-analysis for file: {}, clearing existing results", fileId);
    packetRepository.deleteByFileId(fileId);
    conversationRepository.deleteByFileId(fileId);
    analysisResultRepository.deleteByFileId(fileId);
    analyzeFile(fileId);
  }

  @Transactional
  public void analyzeFile(UUID fileId) {
    log.info("Starting analysis for file: {}", fileId);

    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    // Check if already analyzed
    if (analysisResultRepository.existsByFileId(fileId)) {
      log.info("File {} already analyzed, skipping", fileId);
      return;
    }

    try {
      // Create initial analysis record
      AnalysisResultEntity analysis =
          AnalysisResultEntity.builder()
              .file(file)
              .status(AnalysisResultEntity.AnalysisStatus.IN_PROGRESS)
              .build();
      analysis = analysisResultRepository.save(analysis);

      // Download file from MinIO to temp location
      File tempFile = File.createTempFile("pcap-", ".pcap");
      storageService.downloadFileToLocal(file.getMinioPath(), tempFile);

      // Parse PCAP file
      PcapParserService.PcapAnalysisResult parseResult =
          pcapParserService.analyzePcapFile(tempFile);

      // Enrich conversations with app names and security risks via nDPI (single subprocess run)
      ndpiService.enrich(tempFile, parseResult.getConversations());

      // Apply custom user-defined signature rules (appends matched rule names to flowRisks)
      customSignatureService.applySignatures(parseResult.getConversations());

      // Update analysis results
      analysis.setPacketCount(parseResult.getPacketCount());
      analysis.setTotalBytes(parseResult.getTotalBytes());
      analysis.setStartTime(parseResult.getStartTime());
      analysis.setEndTime(parseResult.getEndTime());

      if (parseResult.getStartTime() != null && parseResult.getEndTime() != null) {
        Duration duration = Duration.between(parseResult.getStartTime(), parseResult.getEndTime());
        analysis.setDurationMs(duration.toMillis());
      }

      // Convert protocol counts to JSON format
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

      // Save conversations and their packets.
      // Packets are built and saved in PACKET_BATCH_SIZE chunks per conversation so we
      // never hold more than one batch of PacketEntity objects in memory at a time.
      // After each conversation's packets are persisted the source PacketInfo list is
      // cleared so the parser's heap footprint shrinks progressively during this phase.
      // Every JPA_FLUSH_INTERVAL conversations we flush+clear the JPA session to prevent
      // Hibernate's first-level cache from accumulating all saved entities.
      int convIndex = 0;
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
                .category(convInfo.getCategory())
                .hostname(convInfo.getHostname())
                .ja3Client(convInfo.getJa3Client())
                .ja3Server(convInfo.getJa3Server())
                .tlsIssuer(convInfo.getTlsIssuer())
                .tlsSubject(convInfo.getTlsSubject())
                .tlsNotBefore(convInfo.getTlsNotBefore())
                .tlsNotAfter(convInfo.getTlsNotAfter())
                .flowRisks(convInfo.getFlowRisks().isEmpty()
                    ? null
                    : convInfo.getFlowRisks().toArray(new String[0]))
                .customSignatures(convInfo.getCustomSignatures().isEmpty()
                    ? null
                    : convInfo.getCustomSignatures().toArray(new String[0]))
                .packetCount(convInfo.getPacketCount())
                .totalBytes(convInfo.getTotalBytes())
                .startTime(convInfo.getStartTime())
                .endTime(convInfo.getEndTime())
                .build();
        ConversationEntity savedConversation = conversationRepository.save(conversation);

        List<PcapParserService.PacketInfo> packetInfos = convInfo.getPackets();
        if (!packetInfos.isEmpty()) {
          // Build and save one batch at a time — avoids materialising the full PacketEntity list
          for (int i = 0; i < packetInfos.size(); i += PACKET_BATCH_SIZE) {
            int end = Math.min(i + PACKET_BATCH_SIZE, packetInfos.size());
            List<PacketEntity> batch = packetInfos.subList(i, end).stream()
                .map(pktInfo -> PacketEntity.builder()
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
          }
          // Free the parsed packet list — memory is released as each conversation is saved
          packetInfos.clear();
        }

        // Periodically flush and clear the JPA session so Hibernate's first-level cache
        // doesn't accumulate every saved entity for the lifetime of the transaction
        if (++convIndex % JPA_FLUSH_INTERVAL == 0) {
          entityManager.flush();
          entityManager.clear();
        }
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

      // Cleanup temp file
      tempFile.delete();

      log.info("Analysis completed for file: {}", fileId);

    } catch (Exception e) {
      log.error("Error analyzing file {}: {}", fileId, e.getMessage(), e);

      // Mark analysis as failed
      analysisResultRepository
          .findByFileId(fileId)
          .ifPresent(
              analysis -> {
                analysis.setStatus(AnalysisResultEntity.AnalysisStatus.FAILED);
                analysis.setErrorMessage(e.getMessage());
                analysisResultRepository.save(analysis);
              });

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
              long[] stats = appStatsMap.computeIfAbsent(conv.getAppName(), k -> new long[] {0L, 0L});
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

    // Aggregate category distribution
    class CategoryAggregate {
      long packetCount = 0L;
      long totalBytes  = 0L;
    }
    Map<String, CategoryAggregate> catStatsMap = new java.util.TreeMap<>();
    conversations.stream()
        .filter(conv -> conv.getCategory() != null && !conv.getCategory().isBlank())
        .forEach(
            conv -> {
              CategoryAggregate agg = catStatsMap.computeIfAbsent(conv.getCategory(), k -> new CategoryAggregate());
              agg.packetCount += conv.getPacketCount() != null ? conv.getPacketCount() : 0L;
              agg.totalBytes  += conv.getTotalBytes() != null ? conv.getTotalBytes() : 0L;
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
                        .percentage(totalCatPackets > 0
                            ? (e.getValue().packetCount * 100.0 / totalCatPackets) : 0.0)
                        .build())
            .sorted(java.util.Comparator.comparingLong(AnalysisSummaryResponse.CategoryStat::getCount).reversed())
            .collect(Collectors.toList());

    long securityAlertCount = conversations.stream()
        .filter(conv -> (conv.getFlowRisks() != null && conv.getFlowRisks().length > 0)
            || (conv.getCustomSignatures() != null && conv.getCustomSignatures().length > 0))
        .count();

    List<String> triggeredCustomRules = conversations.stream()
        .filter(conv -> conv.getCustomSignatures() != null && conv.getCustomSignatures().length > 0)
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
                        .flowRisks(conv.getFlowRisks() != null
                            ? Arrays.asList(conv.getFlowRisks()) : List.of())
                        .customSignatures(conv.getCustomSignatures() != null
                            ? Arrays.asList(conv.getCustomSignatures()) : List.of())
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

    List<ConversationResponse> content = dbPage.getContent().stream()
        .map(this::toConversationResponse)
        .collect(Collectors.toList());

    return PagedResponse.of(content, dbPage.getTotalElements(), page, pageSize);
  }

  /** Returns distinct detected file types found in packets for the given file. */
  @Transactional(readOnly = true)
  public List<String> getDistinctFileTypes(UUID fileId) {
    return conversationRepository.findDistinctFileTypesByFileId(fileId);
  }

  /** Returns distinct nDPI risk type strings present in at-risk conversations for the given file. */
  @Transactional(readOnly = true)
  public List<String> getDistinctRiskTypes(UUID fileId) {
    return conversationRepository.findDistinctRiskTypesByFileId(fileId);
  }

  @Transactional(readOnly = true)
  public List<String> getDistinctCustomSignatures(UUID fileId) {
    return conversationRepository.findDistinctCustomSignaturesByFileId(fileId);
  }

  /** Also used by the CSV export — returns ALL matching rows without pagination. */
  @Transactional(readOnly = true)
  public List<ConversationResponse> getConversationsForExport(
      UUID fileId, ConversationFilterParams params) {

    Sort sort = buildSort(params);
    Specification<ConversationEntity> spec = ConversationRepository.buildSpec(fileId, params);
    return conversationRepository.findAll(spec, sort).stream()
        .map(this::toConversationResponse)
        .collect(Collectors.toList());
  }

  private Sort buildSort(ConversationFilterParams params) {
    if (params == null || params.getSortBy() == null || params.getSortBy().isBlank()) {
      return Sort.unsorted();
    }
    // Map frontend field names to entity field names
    String field = switch (params.getSortBy()) {
      case "packets"   -> "packetCount";
      case "bytes"     -> "totalBytes";
      case "duration"  -> "startTime"; // duration is computed; proxy with startTime
      default          -> params.getSortBy(); // srcIp, dstIp, startTime pass through
    };
    Sort.Direction dir = "desc".equalsIgnoreCase(params.getSortDir())
        ? Sort.Direction.DESC : Sort.Direction.ASC;
    return Sort.by(dir, field);
  }

  private ConversationResponse toConversationResponse(ConversationEntity conv) {
    Duration duration = Duration.between(conv.getStartTime(), conv.getEndTime());
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
        .flowRisks(conv.getFlowRisks() != null ? Arrays.asList(conv.getFlowRisks()) : List.of())
        .customSignatures(conv.getCustomSignatures() != null ? Arrays.asList(conv.getCustomSignatures()) : List.of())
        .packetCount(conv.getPacketCount())
        .totalBytes(conv.getTotalBytes())
        .startTime(conv.getStartTime())
        .endTime(conv.getEndTime())
        .durationMs(duration.toMillis())
        .build();
  }

  @Transactional(readOnly = true)
  public List<ConversationResponse> getSecurityAlerts(UUID fileId) {
    List<ConversationEntity> conversations = conversationRepository.findByFileIdWithRisks(fileId);

    return conversations.stream()
        .map(conv -> {
          Duration duration = Duration.between(conv.getStartTime(), conv.getEndTime());
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
              .flowRisks(conv.getFlowRisks() != null
                  ? Arrays.asList(conv.getFlowRisks()) : List.of())
              .customSignatures(conv.getCustomSignatures() != null
                  ? Arrays.asList(conv.getCustomSignatures()) : List.of())
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
                () ->
                    new ResourceNotFoundException("Conversation not found: " + conversationId));

    List<PacketEntity> packets =
        packetRepository.findByConversationIdOrderByPacketNumberAsc(conversationId);

    Duration duration = Duration.between(conversation.getStartTime(), conversation.getEndTime());

    List<PacketResponse> packetResponses =
        packets.stream().map(this::toPacketResponse).collect(Collectors.toList());

    return ConversationDetailResponse.builder()
        .conversationId(conversation.getId())
        .srcIp(conversation.getSrcIp())
        .srcPort(conversation.getSrcPort())
        .dstIp(conversation.getDstIp())
        .dstPort(conversation.getDstPort())
        .protocol(conversation.getProtocol())
        .appName(conversation.getAppName())
        .category(conversation.getCategory())
        .hostname(conversation.getHostname())
        .ja3Client(conversation.getJa3Client())
        .ja3Server(conversation.getJa3Server())
        .tlsIssuer(conversation.getTlsIssuer())
        .tlsSubject(conversation.getTlsSubject())
        .tlsNotBefore(conversation.getTlsNotBefore())
        .tlsNotAfter(conversation.getTlsNotAfter())
        .flowRisks(conversation.getFlowRisks() != null
            ? Arrays.asList(conversation.getFlowRisks()) : List.of())
        .customSignatures(conversation.getCustomSignatures() != null
            ? Arrays.asList(conversation.getCustomSignatures()) : List.of())
        .packetCount(conversation.getPacketCount())
        .totalBytes(conversation.getTotalBytes())
        .startTime(conversation.getStartTime())
        .endTime(conversation.getEndTime())
        .durationMs(duration.toMillis())
        .packets(packetResponses)
        .build();
  }
}
