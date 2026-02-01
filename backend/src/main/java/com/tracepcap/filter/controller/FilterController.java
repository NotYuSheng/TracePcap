package com.tracepcap.filter.controller;

import com.tracepcap.filter.dto.*;
import com.tracepcap.filter.service.FilterService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST controller for filter generation and execution
 */
@Slf4j
@RestController
@RequestMapping("/api/filter")
@RequiredArgsConstructor
@Tag(name = "Filter Generator", description = "APIs for natural language to pcap filter generation and execution")
public class FilterController {

    private final FilterService filterService;

    @PostMapping("/generate/{fileId}")
    @Operation(
            summary = "Generate filter from natural language",
            description = "Uses AI to convert a natural language query into a BPF filter expression"
    )
    public ResponseEntity<FilterGenerationResponse> generateFilter(
            @PathVariable String fileId,
            @Valid @RequestBody FilterGenerationRequest request) {

        log.info("Generating filter for file {} with query: {}", fileId, request.getNaturalLanguageQuery());

        FilterGenerationResponse response = filterService.generateFilter(
                UUID.fromString(fileId),
                request.getNaturalLanguageQuery()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/execute/{fileId}")
    @Operation(
            summary = "Execute filter on PCAP file with pagination",
            description = "Applies a BPF filter to a PCAP file and returns matching packets with pagination support"
    )
    public ResponseEntity<FilterExecutionResponse> executeFilter(
            @PathVariable String fileId,
            @Valid @RequestBody FilterExecutionRequest request,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "25") int pageSize) {

        log.info("Executing filter on file {}: {} (page: {}, pageSize: {})",
                 fileId, request.getFilter(), page, pageSize);

        // Validate pagination parameters
        if (page < 1) {
            page = 1;
        }
        if (pageSize < 1 || pageSize > 100) {
            pageSize = 25; // Default to 25 if invalid
        }

        FilterExecutionResponse response = filterService.executeFilter(
                UUID.fromString(fileId),
                request.getFilter(),
                page,
                pageSize
        );

        return ResponseEntity.ok(response);
    }
}
