package com.tracepcap.story.dto;

import java.util.List;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConversationEvidence {
  private String srcIp;
  private Integer srcPort;
  private String dstIp;
  private Integer dstPort;
  private String protocol;
  private String appName;
  private String category;
  private String hostname;
  private Long totalBytes;
  private Long packetCount;
  private String startTime;
  private String endTime;
  private List<String> flowRisks;
  private String tlsIssuer;
  private String tlsSubject;
  private String ja3Client;
}
