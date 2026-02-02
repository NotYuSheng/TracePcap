package com.tracepcap.filter.dto;

import java.util.List;
import lombok.Builder;
import lombok.Data;

/** Response containing the generated filter */
@Data
@Builder
public class FilterGenerationResponse {

  private String filter;

  private String explanation;

  private Double confidence;

  private List<String> suggestions;
}
