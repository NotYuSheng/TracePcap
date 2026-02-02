package com.tracepcap.story.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Story response DTO */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StoryResponse {
  private String id;
  private String fileId;
  private Long generatedAt;
  private List<NarrativeSection> narrative;
  private List<Highlight> highlights;
  private List<StoryTimelineEvent> timeline;
}
