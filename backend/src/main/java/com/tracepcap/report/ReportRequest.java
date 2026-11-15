package com.tracepcap.report;

import java.util.List;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Optional diagram images (base64-encoded PNGs) and active filter labels sent by the frontend. */
@Data
@NoArgsConstructor
public class ReportRequest {
  private String forceDirectedImage;
  private String hierarchicalImage;
  /** Human-readable labels for each active network-diagram filter, e.g. "Protocol: HTTPS". */
  private List<String> activeFilters;
  /** Node-limit banner text when not all nodes are shown, e.g. "Showing the 50 most significant nodes (428 hidden)…". */
  private String nodeLimitNote;
  /**
   * The network the capture is viewed in (#925): its own detection rules' matches are included,
   * and the global rules it switches off are left out. Null for the shared rules only.
   */
  private java.util.UUID networkId;
}
