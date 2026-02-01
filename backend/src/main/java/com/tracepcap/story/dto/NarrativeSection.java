package com.tracepcap.story.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Narrative section in a story
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NarrativeSection {
    private String title;
    private String content;
    private SectionType type;
    private RelatedData relatedData;

    public enum SectionType {
        summary, detail, anomaly, conclusion
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RelatedData {
        private List<String> packets;
        private List<String> conversations;
        private List<String> hosts;
    }
}
