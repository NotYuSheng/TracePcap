package com.tracepcap.filter.dto;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;

/**
 * Request for executing a filter on a PCAP file
 */
@Data
public class FilterExecutionRequest {

    @NotBlank(message = "Filter is required")
    private String filter;
}
