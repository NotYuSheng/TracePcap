package com.tracepcap.story.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
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
  private List<String> suggestedQuestions;

  /** Pre-computed aggregates over the full conversation dataset. Null for legacy cached stories. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private StoryAggregates aggregates;

  /** Deterministic findings computed by the detector pipeline. Null for legacy cached stories. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private List<Finding> findings;

  /**
   * LLM-directed investigation steps: hypotheses, queries, and retrieved conversation evidence.
   * Null for legacy cached stories.
   */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private List<InvestigationStep> investigationSteps;
}
