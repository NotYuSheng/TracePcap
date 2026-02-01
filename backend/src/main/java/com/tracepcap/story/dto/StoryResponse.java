package com.tracepcap.story.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Story response DTO
 */
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
