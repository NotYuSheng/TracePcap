package com.tracepcap.story.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

/** Request body for story generation */
@Data
@NoArgsConstructor
public class GenerateStoryRequest {
  private String additionalContext;
  /** Pre-built prompt supplied by the user (used when retrying after a context-length error). */
  private String customPrompt;
  /** Max number of findings to include in the prompt (default 20). */
  private Integer maxFindings;
  /** Max number of protocol risk matrix entries to include in the prompt (default 15). */
  private Integer maxRiskMatrix;
}
