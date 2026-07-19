package com.tracepcap.file.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** DTO for file metadata */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FileMetadataDto {

  private String fileId;

  private String fileName;

  private Long fileSize;

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime uploadedAt;

  private String status;

  private String source;

  // Per-file analysis stage toggles chosen at upload time. Surfaced so the UI can flag files
  // that ran a partial analysis (e.g. Suricata IDS skipped).
  private boolean enableNdpi;

  private boolean enableSuricata;

  private boolean enableFileExtraction;

  // Rough pre-analysis time estimate (seconds), derived from file size and which analysis stages
  // are effectively enabled for this file (nDPI / Suricata / file extraction). Lets the loading
  // view show an estimate that reflects the user's upload choices instead of a size-only guess.
  private Integer estimatedAnalysisSeconds;

  private Integer packetCount;

  private Long duration;

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime startTime;

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime endTime;
}
