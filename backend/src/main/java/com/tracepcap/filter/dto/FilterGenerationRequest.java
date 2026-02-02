package com.tracepcap.filter.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Request for generating a filter from natural language */
@Data
public class FilterGenerationRequest {

  @NotBlank(message = "Natural language query is required")
  private String naturalLanguageQuery;
}
