package com.tracepcap.tracer.dto;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TracerExplainResponse {
  private String conversationId;
  private List<StepExplanation> explanations;
  /** Non-null when the LLM was unreachable or returned an error. */
  private String error;
}
