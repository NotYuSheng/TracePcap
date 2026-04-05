package com.tracepcap.report;

import lombok.Data;
import lombok.NoArgsConstructor;

/** Optional diagram images (base64-encoded PNGs) sent by the frontend. */
@Data
@NoArgsConstructor
public class ReportRequest {
  private String forceDirectedImage;
  private String hierarchicalImage;
}
