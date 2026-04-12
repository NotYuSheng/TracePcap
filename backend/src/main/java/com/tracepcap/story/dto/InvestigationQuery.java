package com.tracepcap.story.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InvestigationQuery {
  private String id;
  private String label;
  private String srcIp;
  private String dstIp;
  private Integer dstPort;
  private String protocol;
  private String appName;
  private String category;
  private Boolean hasRisks;
  private Boolean hasTlsAnomaly;
  private String riskType;
  private Long minBytes;
  private Long maxBytes;
  private Integer minFlows;
}
