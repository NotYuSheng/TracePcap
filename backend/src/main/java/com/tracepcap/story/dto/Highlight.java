package com.tracepcap.story.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Highlight/anomaly in a story */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Highlight {
  private String id;
  private HighlightType type;
  private String title;
  private String description;
  private Long timestamp;

  public enum HighlightType {
    anomaly,
    insight,
    warning,
    info
  }
}
