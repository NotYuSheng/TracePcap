package com.tracepcap.signatures.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** A Re-apply run (#925 phase 2) and its progress. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RuleReapplyJobDto {
  private UUID id;
  /** The one capture it was started for, or null for every out-of-date capture. */
  private UUID fileId;
  /** RUNNING, DONE, FAILED, or INTERRUPTED (the backend restarted mid-run; start it again). */
  private String status;
  private int total;
  private int done;
  private int failed;
  private String error;
  private String requestedBy;
  private LocalDateTime createdAt;
  private LocalDateTime finishedAt;
}
