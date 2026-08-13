package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.AnalysisProgressResponse;
import com.tracepcap.analysis.dto.AnalysisSummaryResponse;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.dto.ProtocolStatsResponse;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.entity.PacketEntity;
import com.tracepcap.analysis.entity.IpMacObservationEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.repository.IpMacObservationRepository;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.analysis.spi.ExtractionManifest;
import com.tracepcap.analysis.spi.FileExtractionStage;
import com.tracepcap.analysis.spi.HostClassifier;
import com.tracepcap.analysis.spi.PacketPartitions;
import com.tracepcap.analysis.spi.SignatureApplier;
import com.tracepcap.analysis.spi.ServiceLogRoles;
import com.tracepcap.analysis.spi.HostServiceLogExtractor;
import com.tracepcap.analysis.spi.HostServiceLogResult;
import com.tracepcap.analysis.spi.HostServiceSuspicion;
import com.tracepcap.common.event.AnalysisCompletedEvent;
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

  // Global Suricata kill-switch (SURICATA_ENABLED). When false, Suricata is skipped for every file
  // regardless of the per-file enableSuricata flag. Suricata dominates per-file analysis cost, so
  // this is the single biggest throughput lever. See application.yml.
  // Flush interval: how many conversations to process before flushing the JPA session.
  // Keeps the Hibernate first-level cache from accumulating unbounded saved entities.
  private static final int JPA_FLUSH_INTERVAL = 50;

  // ---- Live progress stage plan -------------------------------------------------------------
  // One step per pipeline stage that will actually run for a file. The weights are relative shares
  // of total wall-clock time (roughly the same reasoning as FileMapper's ETA coefficients) so the
  // progress bar advances in realistic proportions rather than in equal jumps. Suricata dominates,
  // so the Extract stage's weight scales with the enabled analysers. Skipped stages are omitted
  // entirely, which also drives totalStages ("Stage 6 of 6").
  private record StageStep(String label, int weight) {}

  /** Builds the ordered list of stages that will run for {@code file}, given its enabled options. */
  private static List<StageStep> buildStagePlan(FileEntity file) {
    boolean ndpi = file.isEnableNdpi();
    // Weight only: the effective Suricata state (incl. the global kill-switch) is decided inside the
    // extractor; using the per-file flag here is a close-enough heuristic for bar proportions.
    boolean suricata = file.isEnableSuricata();
    List<StageStep> plan = new ArrayList<>();
    plan.add(new StageStep("Downloading capture", 3));
    plan.add(new StageStep("Parsing packets", 20));
    plan.add(new StageStep("Detecting applications & threats", 5 + (ndpi ? 10 : 0) + (suricata ? 20 : 0)));
    plan.add(new StageStep("Classifying hosts & geo-locating", 12));
    plan.add(new StageStep("Saving analysis summary", 2));
    plan.add(new StageStep("Writing conversations & packets", 20));
    if (file.isEnableFileExtraction()) {
      plan.add(new StageStep("Extracting transferred files", 8));
    }
    return plan;
  }

  /**
   * Publishes progress for the stage at {@code index} (0-based). {@code percent} is the weighted
   * fraction of work completed <em>before</em> this stage begins, so the bar reflects finished work
   * only — it never claims interior progress on an opaque external stage.
   */
  private void reportStage(UUID fileId, List<StageStep> plan, int index) {
    // Defensive: indices are hardcoded at the call sites against buildStagePlan. A mismatch (e.g. a
    // stage added/removed without updating both) should degrade to no progress, not crash analysis.
    if (index < 0 || index >= plan.size()) {
      log.warn("reportStage: index {} out of range for plan of size {}", index, plan.size());
      return;
    }
    int totalWeight = plan.stream().mapToInt(StageStep::weight).sum();
    int doneWeight = 0;
    for (int i = 0; i < index; i++) doneWeight += plan.get(i).weight();
    int percent = totalWeight > 0 ? (int) Math.round(doneWeight * 100.0 / totalWeight) : 0;
    analysisProgressService.update(
        fileId,
        new AnalysisProgressResponse(index + 1, plan.size(), plan.get(index).label(), percent));
  }

  @PersistenceContext private EntityManager entityManager;

  private final AnalysisResultRepository analysisResultRepository;
  private final ConversationRepository conversationRepository;
  private final PacketRepository packetRepository;
  private final PacketPartitions packetPartitions;
  private final HostClassificationRepository hostClassificationRepository;
  private final IpMacObservationRepository ipMacObservationRepository;
  private final FileRepository fileRepository;
  private final StorageService storageService;
  private final PcapParserService pcapParserService;
  // No extractor fields: the runner discovers every Extractor. Adding one touches nothing here.
  private final ExtractorRunner extractorRunner;
  private final SignatureApplier signatureApplier;
  private final HostClassifier hostClassifier;
  private final HostnameResolverService hostnameResolverService;
  private final List<HostServiceLogExtractor> hostServiceLogExtractors;
  private final GeoIpService geoIpService;
  private final FileExtractionStage fileExtractionStage;
  private final AnalysisRecordService analysisRecordService;
  private final AnalysisProgressService analysisProgressService;
  private final ExtractionRunService extractionRunService;
  private final HostnameAdjudicator hostnameAdjudicator;
  private final org.springframework.context.ApplicationEventPublisher eventPublisher;
  private final HostnameClaimWriter hostnameClaimWriter;

  /**
   * Runs the capture through the pipeline (#512 slice 7).
   *
   * <p>This was one 290-line method with the stages marked by comments, which meant the stage
   * boundaries were a claim rather than a fact: anything could read anything, and "which stage
   * writes this?" was answered by scrolling. Each stage is now a method taking an explicit {@link
   * Run}, so what a stage consumes and produces is in its signature.
   *
   * <p>What stays here is what genuinely belongs to the whole job: the guard against re-analysis,
   * the temp file's lifetime, and the failure path — which has to mark the record FAILED in its own
   * committed transaction, since the one being rolled back cannot record why it failed.
   */
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

    // Live progress plan: which stages will run for this file, and their relative weights.
    List<StageStep> plan = buildStagePlan(file);

    try {
      long analysisStart = System.currentTimeMillis();
      Run run = new Run(fileId, file, plan, analysis);

      File tempFile = File.createTempFile("pcap-", ".pcap");
      run.pcap = tempFile;
      try {
        downloadCapture(run);
        parseCapture(run);
        runExtractors(run);
        enrichAndClassify(run);
        persistAnalysisResult(run);
        persistConversationsAndPackets(run);
        extractEmbeddedFiles(run);
        completeFile(run);

        log.info(
            "[{}] Analysis complete: total {}ms",
            fileId,
            System.currentTimeMillis() - analysisStart);

      } finally {
        tempFile.delete();
        // Stop tracking live progress: on success the poller flips to the 200 summary; on failure
        // it flips to 500. Either way the in-memory entry is no longer needed.
        analysisProgressService.clear(fileId);
      }

    } catch (Exception e) {
      log.error("Error analyzing file {}: {}", fileId, e.getMessage(), e);

      // Clear progress on every failure path, including ones that never reached the inner finally
      // (e.g. createTempFile throwing after the first reportStage). Idempotent — safe if already done.
      analysisProgressService.clear(fileId);

      // Mark analysis and file as FAILED in a separate committed transaction so the status persists
      // even though the outer transaction is being rolled back.
      try {
        analysisRecordService.markFailed(analysis.getId(), fileId, e.getMessage());
      } catch (Exception markEx) {
        log.error(
            "Failed to mark analysis {} as FAILED: {}", analysis.getId(), markEx.getMessage());
      }

      throw new RuntimeException("Failed to analyze file", e);
    }
  }

  /**
   * State handed from one stage to the next.
   *
   * <p>Mutable and package-private on purpose: the stages genuinely form a chain, and pretending
   * otherwise by threading a growing tuple of return values would obscure that. Fields are written
   * by exactly one stage and read by later ones, which is the property worth having — and one that
   * was not checkable at all while everything was a local variable in a single method.
   */
  private static final class Run {
    final UUID fileId;
    final FileEntity file;
    final List<StageStep> plan;
    final AnalysisResultEntity analysis;

    /** Stage 1 writes; stages 2, 3, 4 and 7 read. Deleted by the caller's finally. */
    File pcap;

    /** Stage 2 writes; every later stage reads. */
    PcapParserService.PcapAnalysisResult parseResult;

    /** Stage 6 writes; stage 7 reads. */
    List<UUID> savedConversationIds = List.of();

    Run(UUID fileId, FileEntity file, List<StageStep> plan, AnalysisResultEntity analysis) {
      this.fileId = fileId;
      this.file = file;
      this.plan = plan;
      this.analysis = analysis;
    }
  }

  // ── Stage 1: download ───────────────────────────────────────────────────────

  private void downloadCapture(Run run) {
    reportStage(run.fileId, run.plan, 0);
    long t = System.currentTimeMillis();
    storageService.downloadFileToLocal(run.file.getMinioPath(), run.pcap);
    log.info("[{}] [1/7] Download: {}ms", run.fileId, System.currentTimeMillis() - t);
  }

  // ── Stage 2: parse ──────────────────────────────────────────────────────────

  private void parseCapture(Run run) {
    reportStage(run.fileId, run.plan, 1);
    long t = System.currentTimeMillis();
    run.parseResult = pcapParserService.analyzePcapFile(run.pcap);
    log.info(
        "[{}] [2/7] PCAP parse: {}ms  ({} packets, {} conversations)",
        run.fileId,
        System.currentTimeMillis() - t,
        run.parseResult.getPacketCount(),
        run.parseResult.getConversations().size());
  }

  // ── Stage 3: extract ────────────────────────────────────────────────────────

  /**
   * Every {@code Extractor} on the classpath, in turn.
   *
   * <p>This block used to name each extractor, hold its enable flag, and record its manifest row by
   * hand; adding one meant editing this method. It now names none of them: the runner discovers
   * every Extractor, each decides for itself whether it applies to this capture, and the manifest
   * row is automatic (#512).
   */
  private void runExtractors(Run run) {
    reportStage(run.fileId, run.plan, 2);
    long t = System.currentTimeMillis();
    extractorRunner.runAll(run.file, run.pcap, run.parseResult.getConversations());
    log.info("[{}] [3/7] Extract: {}ms", run.fileId, System.currentTimeMillis() - t);
  }

  // ── Stage 4: signatures, classification, geo-IP ─────────────────────────────

  private void enrichAndClassify(Run run) {
    reportStage(run.fileId, run.plan, 3);
    long t = System.currentTimeMillis();
    UUID fileId = run.fileId;

    Map<String, String> deviceOverrides =
        signatureApplier.applySignatures(run.parseResult.getConversations());

    // resolve() degrades gracefully and never throws. Claims are persisted conflict-preserving
    // (#512 slice 4); the adjudicator picks display winners with the same semantics the
    // resolver used to apply at write time, so downstream behaviour is unchanged.
    List<HostnameResolverService.Claim> hostnameClaims = hostnameResolverService.resolve(run.pcap);
    try {
      hostnameClaimWriter.replaceForFile(fileId, hostnameClaims);
    } catch (Exception e) {
      // Best-effort: the writer's REQUIRES_NEW tx rolled back alone; analysis continues.
      log.warn(
          "Failed to persist {} hostname claim(s) for file {}: {}",
          hostnameClaims.size(),
          fileId,
          e.getMessage());
    }
    Map<String, HostnameResolverService.ResolvedHostname> hostnames =
        hostnameAdjudicator.adjudicate(hostnameClaims);

    // Per-host service activity logs (DNS today; web servers etc. later). Each extractor runs
    // one tshark pass, persists its own rows, and reports which hosts serve its role + any
    // suspicious ones. Runs before classification so a host's roles can drive its device type
    // (e.g. a DNS responder → DNS_SERVER). Adding a role needs no change here.
    ServiceLogOutcome serviceLogs = runServiceLogExtractors(run.file, run.pcap);

    List<HostClassificationEntity> hostClassifications =
        hostClassifier.classify(
            run.file,
            run.parseResult.getConversations(),
            run.parseResult.getHostTtls(),
            run.parseResult.getHostMacs(),
            deviceOverrides,
            hostnames,
            serviceLogs.rolesByIp());
    applyServiceLogSuspicions(hostClassifications, serviceLogs.suspicions());
    hostClassificationRepository.saveAll(hostClassifications);

    try {
      persistIpMacObservations(run.file, run.parseResult.getHostMacObservations());
    } catch (Exception e) {
      // Quiet, low-false-positive supplementary signal — never fail the whole analysis for it.
      log.warn("Failed to persist IP/MAC observations for file {}: {}", fileId, e.getMessage());
    }

    try {
      Set<String> allIps =
          run.parseResult.getConversations().stream()
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
  }

  // ── Stage 5: persist the analysis result ────────────────────────────────────

  private void persistAnalysisResult(Run run) {
    reportStage(run.fileId, run.plan, 4);
    long t = System.currentTimeMillis();
    AnalysisResultEntity analysis = run.analysis;
    PcapParserService.PcapAnalysisResult parseResult = run.parseResult;

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
    log.info("[{}] [5/7] Analysis result saved: {}ms", run.fileId, System.currentTimeMillis() - t);
  }

  // ── Stage 6: conversation and packet inserts ────────────────────────────────

  private void persistConversationsAndPackets(Run run) {
    reportStage(run.fileId, run.plan, 5);
    long t = System.currentTimeMillis();
    UUID fileId = run.fileId;

    // `packets` is LIST-partitioned on file_id (#394) and has no default partition, so the
    // partition must exist before the first insert below or the row has nowhere to land.
    packetPartitions.ensurePartition(fileId);

    int convIndex = 0;
    long packetsInserted = 0;
    List<UUID> savedConversationIds = new ArrayList<>();

    for (PcapParserService.ConversationInfo convInfo : run.parseResult.getConversations()) {
      ConversationEntity conversation =
          ConversationEntity.builder()
              .file(run.file)
              .srcIp(convInfo.getSrcIp())
              .srcPort(convInfo.getSrcPort())
              .dstIp(convInfo.getDstIp())
              .dstPort(convInfo.getDstPort())
              .protocol(convInfo.getProtocol())
              .initiatorIp(convInfo.getInitiatorIp())
              .initiatorPort(convInfo.getInitiatorPort())
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
                              .file(run.file)
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
        // Released as we go: a large capture's packet payloads do not all fit in heap at once.
        packetInfos.clear();
      }

      if (++convIndex % JPA_FLUSH_INTERVAL == 0) {
        entityManager.flush();
        entityManager.clear();
        log.info(
            "[{}] [6/7] DB insert progress: {}/{} conversations, {} packets",
            fileId,
            convIndex,
            run.parseResult.getConversations().size(),
            packetsInserted);
      }
    }

    run.savedConversationIds = savedConversationIds;
    log.info(
        "[{}] [6/7] DB inserts done: {}ms  ({} conversations, {} packets)",
        fileId,
        System.currentTimeMillis() - t,
        run.parseResult.getConversations().size(),
        packetsInserted);
  }

  // ── Stage 7: carve embedded files ───────────────────────────────────────────

  /** Optional, and never fatal: a capture with unreadable payloads is still a valid analysis. */
  private void extractEmbeddedFiles(Run run) {
    long t = System.currentTimeMillis();
    if (!run.file.isEnableFileExtraction()) {
      log.info("[{}] [7/7] File extraction: skipped", run.fileId);
      return;
    }
    // Only in the plan when enabled — index 6.
    reportStage(run.fileId, run.plan, 6);
    try {
      fileExtractionStage.extractFiles(run.file, run.pcap, run.savedConversationIds);
      log.info("[{}] [7/7] File extraction: {}ms", run.fileId, System.currentTimeMillis() - t);
    } catch (Exception e) {
      log.warn(
          "[{}] [7/7] File extraction failed ({}ms): {}",
          run.fileId,
          System.currentTimeMillis() - t,
          e.getMessage());
    }
  }

  // ── Completion ──────────────────────────────────────────────────────────────

  private void completeFile(Run run) {
    FileEntity file = run.file;
    PcapParserService.PcapAnalysisResult parseResult = run.parseResult;

    file.setStatus(com.tracepcap.file.entity.FileEntity.FileStatus.COMPLETED);
    file.setPacketCount(
        parseResult.getPacketCount() != null ? parseResult.getPacketCount().intValue() : null);
    file.setTotalBytes(parseResult.getTotalBytes());
    file.setStartTime(parseResult.getStartTime());
    file.setEndTime(parseResult.getEndTime());
    file.setDuration(run.analysis.getDurationMs());
    fileRepository.save(file);

    // AFTER_COMMIT listeners (identity adjudication in insights) fire once this tx lands —
    // the pipeline never learns who is listening (#512 slice 5).
    eventPublisher.publishEvent(new AnalysisCompletedEvent(run.fileId));
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
  /**
   * Persist the distinct source MACs observed per IP (#461). Only IPs with more than one MAC carry
   * overlap signal, but we store all pairings so the detector can present the full evidence.
   */
  private void persistIpMacObservations(
      FileEntity file, Map<String, LinkedHashSet<String>> macsByIp) {
    if (macsByIp == null || macsByIp.isEmpty()) return;
    List<IpMacObservationEntity> rows = new ArrayList<>();
    macsByIp.forEach(
        (ip, macs) ->
            macs.forEach(
                mac ->
                    rows.add(
                        IpMacObservationEntity.builder()
                            .fileId(file.getId())
                            .ip(ip)
                            .mac(mac)
                            .build())));
    if (!rows.isEmpty()) ipMacObservationRepository.saveAll(rows);
  }

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
