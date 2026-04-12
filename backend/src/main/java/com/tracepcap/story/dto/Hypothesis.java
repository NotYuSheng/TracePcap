package com.tracepcap.story.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Hypothesis {
  private String id;
  private String queryRef;
  private String hypothesis;
  private String confidence; // "HIGH" | "MEDIUM" | "LOW"
}
