package com.tracepcap.analysis.dto;

import java.util.Map;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProtocolStatsResponse {
  private UUID fileId;
  private Map<String, ProtocolStat> protocols;

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ProtocolStat {
    private Long packetCount;
    private Long bytes;
    private Double percentage;
  }
}
