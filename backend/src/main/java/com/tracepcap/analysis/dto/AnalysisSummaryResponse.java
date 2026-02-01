package com.tracepcap.analysis.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalysisSummaryResponse {
    private UUID analysisId;
    private UUID fileId;
    private String fileName;
    private Long packetCount;
    private Long totalBytes;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private Long durationMs;
    private String status;
    private String errorMessage;
    private LocalDateTime analyzedAt;
}
