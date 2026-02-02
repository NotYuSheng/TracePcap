package com.tracepcap.filter.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Request for executing a filter on a PCAP file */
@Data
public class FilterExecutionRequest {

  @NotBlank(message = "Filter is required")
  private String filter;
}
