package com.tracepcap.signatures.dto;

import java.time.LocalDateTime;
import java.util.List;
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
  /** Hosts whose machine device type re-scoring changed (#925), across the job. */
  private int reclassifiedCount;
  /** Analyst labels flagged stale because the re-scored evidence points elsewhere. */
  private int staleLabelsCount;
  /** The changes, up to 100: {fileId, ip, from, to, rules}. */
  private List<java.util.Map<String, Object>> reclassified;
  private LocalDateTime createdAt;
  private LocalDateTime finishedAt;
}
