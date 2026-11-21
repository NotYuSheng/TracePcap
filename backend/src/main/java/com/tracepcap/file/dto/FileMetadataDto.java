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

  /** The capture this re-analyses (#915 phase 3); null for an upload. */
  private String derivedFrom;

  /** A re-analysis version rather than an upload. */
  private boolean version;

  private String source;

  // Per-file analysis stage toggles chosen at upload time. Surfaced so the UI can flag files
  // that ran a partial analysis (e.g. Suricata IDS skipped).
  private boolean enableNdpi;

  private boolean enableSuricata;

  private boolean enableFileExtraction;

  /** Kept until deleted: the retention cleanup skips it. */
  private boolean keepForever;
  /** Who uploaded it, or null for captures from before this was recorded. */
  private String uploadedBy;

  /**
   * When it is deleted, if someone extended it past the retention window (serialised like
   * uploadedAt); null means the retention window applies.
   */
  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime expiresAt;

  /** The caller marked it as a favourite. Personal: per account, or the shared profile. */
  private boolean favourite;

  /** The background story asked for at upload: null, QUEUED, WRITING, READY or FAILED. */
  private String storyStatus;

  /** Why the background story failed, when it did. */
  private String storyError;

  // Rough pre-analysis time estimate (seconds), derived from file size and which analysis stages
  // are effectively enabled for this file (nDPI / Suricata / file extraction). Lets the loading
  // view show an estimate that reflects the user's upload choices instead of a size-only guess.
  private Integer estimatedAnalysisSeconds;

  private Integer packetCount;
  /** The raw packets were pruned by packet retention; conversations and results remain (#394). */
  private boolean packetsRemoved;

  private Long duration;

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime startTime;

  @JsonFormat(shape = JsonFormat.Shape.NUMBER)
  private LocalDateTime endTime;
}
