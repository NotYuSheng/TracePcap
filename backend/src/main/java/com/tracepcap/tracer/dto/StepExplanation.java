package com.tracepcap.tracer.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class StepExplanation {
  private int stepIndex;
  private String explanation;
}
