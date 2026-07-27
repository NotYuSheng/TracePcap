package com.tracepcap.file.mapper;

import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.entity.FileEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Mapper for converting between FileEntity and DTOs */
@Component
public class FileMapper {

  // Global Suricata kill-switch (SURICATA_ENABLED). When false, Suricata never ran regardless of
  // the per-file flag, so the DTO must report the effective state — matching ReportService and
  // AnalysisService — otherwise the UI would not flag such files as partial. See AnalysisService.
  @Value("${tracepcap.suricata.enabled:true}")
  private boolean suricataEnabled;

  private static final int MIN_ESTIMATE_SECONDS = 10;

  // ---- Packet-based coefficients (preferred) ----------------------------------------------------
  // Analysis cost is driven by packet COUNT, not bytes: Suricata/nDPI/parse all scale per-packet, so
  // a small but packet-dense capture can take far longer than its size suggests. Seconds per 1000
  // packets, calibrated against a clean OFFLINE run (21.4k packets, GEO_FORCE_OFFLINE): parse+
  // classify+persist+DB ≈ 0.38, extract(nDPI+Suricata) ≈ 2.6, file-extract ≈ 0.04 s/kpkt. Values
  // below keep a small conservative margin (better to slightly over-estimate). Suricata dominates.
  // Only stages that will run contribute. See analysis-eta-calibration notes for recalibration.
  private static final double BASE_SECONDS_PER_KPKT = 0.45; // parse + classify + persist + DB insert
  private static final double NDPI_SECONDS_PER_KPKT = 0.6;
  private static final double SURICATA_SECONDS_PER_KPKT = 2.1;
  private static final double EXTRACTION_SECONDS_PER_KPKT = 0.08;
  private static final double DOWNLOAD_SECONDS_PER_MB = 0.01; // MinIO fetch, size-scaled

  // ---- Size-based fallback (used only when packet count is unknown) ------------------------------
  // e.g. capinfos failed at upload, or a legacy file predating packet-count capture. ~0.5 s/MB
  // all-stages-on, matching the older end-to-end measurement on large captures.
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
      Long fileSize, Integer packetCount, boolean ndpi, boolean suricata, boolean fileExtraction) {
    if (packetCount != null && packetCount > 0) {
      double kPkt = packetCount / 1000.0;
      double perKPkt =
          BASE_SECONDS_PER_KPKT
              + (ndpi ? NDPI_SECONDS_PER_KPKT : 0)
              + (suricata ? SURICATA_SECONDS_PER_KPKT : 0)
              + (fileExtraction ? EXTRACTION_SECONDS_PER_KPKT : 0);
      double downloadTerm =
          fileSize != null ? fileSize / 1024.0 / 1024.0 * DOWNLOAD_SECONDS_PER_MB : 0;
      return Math.max(MIN_ESTIMATE_SECONDS, (int) Math.round(kPkt * perKPkt + downloadTerm));
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
                entity.isEnableFileExtraction()))
        .build();
  }
}
