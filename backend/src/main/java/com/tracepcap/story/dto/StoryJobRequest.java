package com.tracepcap.story.dto;

import java.util.UUID;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Options for writing a capture's story in the background; all optional. */
@Data
@NoArgsConstructor
public class StoryJobRequest {
  /** Anything the LLM can't see in the capture. */
  private String additionalContext;
  /** A prompt cut down by hand, after the last one was too big for the model. */
  private String customPrompt;
  /** Max findings in the prompt (default 20). */
  private Integer maxFindings;
  /** Max protocol risk matrix rows in the prompt (default 15). */
  private Integer maxRiskMatrix;
  /** The network the capture is viewed in (#925): its detection rules apply too. */
  private UUID networkId;
}
