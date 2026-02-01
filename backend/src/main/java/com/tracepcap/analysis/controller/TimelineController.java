package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.TimelineDataDto;
import com.tracepcap.analysis.service.TimelineService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * REST controller for timeline/traffic analysis operations
 */
@Slf4j
@RestController
@RequestMapping("/api/timeline")
@RequiredArgsConstructor
public class TimelineController {

    private final TimelineService timelineService;

    /**
     * Get timeline data for a file with binned traffic statistics
     *
     * @param fileId   The file ID
     * @param interval The time interval in seconds for binning (default: 60)
     * @return List of timeline data points
     */
    @GetMapping("/{fileId}")
    public ResponseEntity<List<TimelineDataDto>> getTimeline(
            @PathVariable UUID fileId,
            @RequestParam(defaultValue = "60") Integer interval) {
        log.info("GET /api/timeline/{} with interval {}s", fileId, interval);

        List<TimelineDataDto> timeline = timelineService.getTimelineData(fileId, interval);
        return ResponseEntity.ok(timeline);
    }

    /**
     * Get timeline data for a specific time range
     *
     * @param fileId   The file ID
     * @param start    Start timestamp (ISO 8601 format)
     * @param end      End timestamp (ISO 8601 format)
     * @param interval The time interval in seconds for binning (default: 60)
     * @return List of timeline data points
     */
    @GetMapping("/{fileId}/range")
    public ResponseEntity<List<TimelineDataDto>> getTimelineRange(
            @PathVariable UUID fileId,
            @RequestParam String start,
            @RequestParam String end,
            @RequestParam(defaultValue = "60") Integer interval) {
        log.info("GET /api/timeline/{}/range from {} to {} with interval {}s",
                fileId, start, end, interval);

        LocalDateTime startTime = LocalDateTime.parse(start);
        LocalDateTime endTime = LocalDateTime.parse(end);

        List<TimelineDataDto> timeline = timelineService.getTimelineDataForRange(
                fileId, startTime, endTime, interval);
        return ResponseEntity.ok(timeline);
    }
}
