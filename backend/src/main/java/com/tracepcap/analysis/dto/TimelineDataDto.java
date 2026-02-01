package com.tracepcap.analysis.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TimelineDataDto {
    private LocalDateTime timestamp;
    private Long packetCount;
    private Long bytes;
    private Map<String, Long> protocols;  // Protocol name -> packet count
}
