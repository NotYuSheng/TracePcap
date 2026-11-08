package com.tracepcap.file.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/** The analysis options for a re-analysis (#915 phase 3). */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ReanalyseRequest {
  private boolean enableNdpi = true;
  private boolean enableSuricata = true;
  private boolean enableFileExtraction = true;
}
