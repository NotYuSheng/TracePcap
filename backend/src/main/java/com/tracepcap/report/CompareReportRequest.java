package com.tracepcap.report;

import java.util.List;
import java.util.UUID;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Request body for the compare-report endpoint. */
@Data
@NoArgsConstructor
public class CompareReportRequest {
  /** IDs of the files included in the comparison. */
  private List<UUID> fileIds;
  /** Display names corresponding to each file ID (same order). */
  private List<String> fileLabels;
  private String forceDirectedImage;
  private String hierarchicalImage;
  private List<String> activeFilters;
  private String nodeLimitNote;
}
