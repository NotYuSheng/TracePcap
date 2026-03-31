package com.tracepcap.story.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

/** Request body for story generation */
@Data
@NoArgsConstructor
public class GenerateStoryRequest {
  private String additionalContext;
}
