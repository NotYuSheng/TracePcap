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
public class ConversationResponse {
  private UUID conversationId;
  private String srcIp;
  private Integer srcPort;
  private String dstIp;
  private Integer dstPort;
  private String protocol;
  private String appName;
  private String category;
  private String hostname;
  private String ja3Client;
  private String ja3Server;
  private String tlsIssuer;
  private String tlsSubject;
  private LocalDateTime tlsNotBefore;
  private LocalDateTime tlsNotAfter;
  private List<String> flowRisks;
  private Long packetCount;
  private Long totalBytes;
  private LocalDateTime startTime;
  private LocalDateTime endTime;
  private Long durationMs;
}
