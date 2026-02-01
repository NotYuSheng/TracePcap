package com.tracepcap.filter.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Response containing the packets matching the filter with pagination
 */
@Data
@Builder
public class FilterExecutionResponse {

    private List<PacketDto> packets;

    private Integer totalMatches;

    private Long executionTime;

    // Pagination fields
    private Integer page;

    private Integer pageSize;

    private Integer totalPages;
}
