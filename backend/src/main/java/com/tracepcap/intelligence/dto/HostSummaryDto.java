package com.tracepcap.intelligence.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class HostSummaryDto {
  private String ip;
  private String hostname;
  private long totalBytes;
  private long packetCount;
  private long conversationCount;
  private long riskCount;
  private String deviceType;
  private String country;
  private String org;
  private String role;
}
