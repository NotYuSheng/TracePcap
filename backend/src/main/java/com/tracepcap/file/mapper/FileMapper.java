package com.tracepcap.file.mapper;

import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.entity.FileEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.tracepcap.common.stage.DetectionEngineStatus;

/** Mapper for converting between FileEntity and DTOs */
@Component
public class FileMapper {

  // Global Suricata kill-switch (SURICATA_ENABLED). When false, Suricata never ran regardless of
  // the per-file flag, so the DTO must report the effective state — matching ReportService and
  // AnalysisService — otherwise the UI would not flag such files as partial. See AnalysisService.
  private final DetectionEngineStatus detectionEngine;

  public FileMapper(DetectionEngineStatus detectionEngine) {
    this.detectionEngine = detectionEngine;
  }

  @Value("${tracepcap.suricata.enabled:true}")
  private boolean suricataEnabled;

  private static final int MIN_ESTIMATE_SECONDS = 10;

  // ---- Packet-based coefficients (preferred) ----------------------------------------------------
  // seconds = fixed + per_kpkt * (packets / 1000), per stage group.
  //
  // The fixed term is the whole point. The previous model had only a per-packet rate, which is why
  // it read 91 minutes for a job of roughly 36 and 10 seconds for one that took 49 — the same
  // missing constant, in opposite directions. Measured cost per 1000 packets falls ~8x between a
  // 250-packet capture and a 45,000-packet one, which is a fixed cost wearing a per-packet costume.
  //
  // Fitted by scripts/calibrate_analysis_eta.py over runs of 2k-45k packets. Re-run it rather than
  // hand-editing these; it reads the timings the pipeline already logs, and it excludes cold-engine
  // runs, which are a different regime rather than outliers.
  private static final double BASE_FIXED_SECONDS = 1.6; // parse + classify + persist + DB insert
  private static final double BASE_SECONDS_PER_KPKT = 0.43;
  private static final double DETECT_FIXED_SECONDS = 0.4; // nDPI + Suricata, engine already warm
  private static final double DETECT_SECONDS_PER_KPKT = 0.04;
  private static final double EXTRACTION_SECONDS_PER_KPKT = 0.43; // file carving, no fixed cost
  private static final double DOWNLOAD_SECONDS_PER_MB = 0.01; // MinIO fetch, size-scaled

  // Suricata builds its detection engine once per process, not once per capture (#569). ~45s,
  // and it dwarfs everything else, so a capture that has to pay it is a different job — the same
  // split the progress bar makes (#758).
  private static final double SURICATA_ENGINE_BUILD_SECONDS = 45.0;

  // ---- Size-based fallback (used only when packet count is unknown) ------------------------------
  // e.g. capinfos failed at upload, or a legacy file predating packet-count capture. Deliberately
  // cruder: bytes are a poor proxy for work, since a packet-dense capture costs far more than its
  // size suggests. Kept only so an estimate exists at all.
  private static final double BASE_SECONDS_PER_MB = 0.15;
  private static final double NDPI_SECONDS_PER_MB = 0.10;
  private static final double SURICATA_SECONDS_PER_MB = 0.20;
  private static final double EXTRACTION_SECONDS_PER_MB = 0.05;

  /**
   * Estimates analysis wall-clock seconds from the effectively-enabled stages. Prefers a
   * packet-count-based estimate (much more accurate — cost tracks packets, not bytes) and falls back
   * to a size-based one when the packet count is not yet known. Only stages that will actually run
   * contribute. Returns at least {@link #MIN_ESTIMATE_SECONDS}; {@code null} when neither packet
   * count nor size is known.
   */
  private Integer estimateAnalysisSeconds(
      Long fileSize,
      Integer packetCount,
      boolean ndpi,
      boolean suricata,
      boolean fileExtraction,
      boolean engineWarm) {
    if (packetCount != null && packetCount > 0) {
      double kPkt = packetCount / 1000.0;
      double seconds = BASE_FIXED_SECONDS + kPkt * BASE_SECONDS_PER_KPKT;
      if (ndpi || suricata) {
        seconds += DETECT_FIXED_SECONDS + kPkt * DETECT_SECONDS_PER_KPKT;
      }
      if (suricata && !engineWarm) {
        seconds += SURICATA_ENGINE_BUILD_SECONDS;
      }
      if (fileExtraction) {
        seconds += kPkt * EXTRACTION_SECONDS_PER_KPKT;
      }
      if (fileSize != null) {
        seconds += fileSize / 1024.0 / 1024.0 * DOWNLOAD_SECONDS_PER_MB;
      }
      return Math.max(MIN_ESTIMATE_SECONDS, (int) Math.round(seconds));
    }
    if (fileSize == null || fileSize <= 0) return null;
    double sizeMb = fileSize / 1024.0 / 1024.0;
    double perMb =
        BASE_SECONDS_PER_MB
            + (ndpi ? NDPI_SECONDS_PER_MB : 0)
            + (suricata ? SURICATA_SECONDS_PER_MB : 0)
            + (fileExtraction ? EXTRACTION_SECONDS_PER_MB : 0);
    return Math.max(MIN_ESTIMATE_SECONDS, (int) Math.round(sizeMb * perMb));
  }

  public FileUploadResponse toUploadResponse(FileEntity entity) {
    return FileUploadResponse.builder()
        .fileId(entity.getId().toString())
        .fileName(entity.getFileName())
        .fileSize(entity.getFileSize())
        .uploadedAt(entity.getUploadedAt())
        .status(entity.getStatus().name().toLowerCase())
        .storageLocation("s3://tracepcap-files/" + entity.getMinioPath())
        .build();
  }

  public FileMetadataDto toMetadataDto(FileEntity entity) {
    // Effective Suricata state honours the global kill-switch, matching the DTO's enableSuricata.
    boolean effectiveSuricata = suricataEnabled && entity.isEnableSuricata();
    return FileMetadataDto.builder()
        .fileId(entity.getId().toString())
        .fileName(entity.getFileName())
        .fileSize(entity.getFileSize())
        .uploadedAt(entity.getUploadedAt())
        .status(entity.getStatus().name().toLowerCase())
        .packetCount(entity.getPacketCount())
        .duration(entity.getDuration())
        .startTime(entity.getStartTime())
        .endTime(entity.getEndTime())
        .source(entity.getSource() != null ? entity.getSource().name() : null)
        .enableNdpi(entity.isEnableNdpi())
        .enableSuricata(effectiveSuricata)
        .enableFileExtraction(entity.isEnableFileExtraction())
        .estimatedAnalysisSeconds(
            estimateAnalysisSeconds(
                entity.getFileSize(),
                entity.getPacketCount(),
                entity.isEnableNdpi(),
                effectiveSuricata,
                entity.isEnableFileExtraction(),
                // Whether this capture pays the one-time ruleset build (#569) is the difference
                // between a ~45s job and a ~2s one, so the estimate has to know.
                detectionEngine.isWarm()))
        .build();
  }
}
