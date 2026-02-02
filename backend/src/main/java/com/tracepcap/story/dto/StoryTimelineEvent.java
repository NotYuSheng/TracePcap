package com.tracepcap.story.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Timeline event in a story */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StoryTimelineEvent {
  private Long timestamp;
  private String title;
  private String description;
  private EventType type;
  private RelatedData relatedData;

  public enum EventType {
    normal,
    suspicious,
    critical
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class RelatedData {
    private List<String> packets;
    private List<String> conversations;
  }
}
