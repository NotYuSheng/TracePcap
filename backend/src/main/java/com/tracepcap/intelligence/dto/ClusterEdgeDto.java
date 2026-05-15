package com.lanturn.intelligence.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClusterEdgeDto {
  private String sourceId;
  private String targetId;
  private long totalBytes;
  private long conversationCount;
  private String dominantProtocol;
}
