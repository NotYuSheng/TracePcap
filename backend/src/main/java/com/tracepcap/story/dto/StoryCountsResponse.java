package com.tracepcap.story.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class StoryCountsResponse {
  private int totalFindings;
  private int totalRiskMatrix;
}
