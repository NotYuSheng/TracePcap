package com.tracepcap.analysis.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalysisSummaryResponse {
  // Core analysis info
  private UUID analysisId;
  private String fileId; // String for frontend compatibility
  private String fileName;
  private Long fileSize;
  private Long uploadTime; // Unix timestamp in milliseconds

  // Traffic statistics
  private Long totalPackets; // Renamed from packetCount for frontend
  private List<Long> timeRange; // [startTime, endTime] as Unix timestamps

  // Protocol and conversation data
  private List<ProtocolStat> protocolDistribution;
  private List<ConversationSummary> topConversations;
  private List<UniqueHost> uniqueHosts;

  // Legacy fields for backward compatibility
  private LocalDateTime startTime;
  private LocalDateTime endTime;
  private Long durationMs;
  private String status;
  private String errorMessage;
  private LocalDateTime analyzedAt;

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ProtocolStat {
    private String protocol;
    private Long count;
    private Double percentage;
    private Long bytes;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ConversationSummary {
    private String id;
    private String srcIp;
    private Integer srcPort;
    private String dstIp;
    private Integer dstPort;
    private String protocol;
    private Long startTime;
    private Long endTime;
    private Long packetCount;
    private Long totalBytes;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class UniqueHost {
    private String ip;
    private Integer port;
    private String hostname;
  }
}
