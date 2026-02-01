package com.tracepcap.filter.dto;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;

/**
 * Request for generating a filter from natural language
 */
@Data
public class FilterGenerationRequest {

    @NotBlank(message = "Natural language query is required")
    private String naturalLanguageQuery;
}
