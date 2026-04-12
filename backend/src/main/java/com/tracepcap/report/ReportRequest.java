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
}
