package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.TimelineDataDto;
import com.tracepcap.analysis.service.TimelineService;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/** REST controller for timeline/traffic analysis operations */
@Slf4j
@Validated
@RestController
@RequestMapping("/api/timeline")
@RequiredArgsConstructor
public class TimelineController {

  private final TimelineService timelineService;

  /**
   * Get timeline data for a file with binned traffic statistics
   *
   * @param fileId The file ID
   * @param interval The time interval in seconds for binning (default: 60)
   * @param maxDataPoints Maximum number of data points to return (optional, uses config default if
   *     not provided)
   * @return List of timeline data points
   */
  @GetMapping("/{fileId}")
  public ResponseEntity<List<TimelineDataDto>> getTimeline(
      @PathVariable UUID fileId,
      @RequestParam(defaultValue = "60")
          @Min(value = 1, message = "interval must be at least 1 second")
          Integer interval,
      @RequestParam(required = false)
          @Min(value = 10, message = "maxDataPoints must be at least 10")
          @Max(value = 10000, message = "maxDataPoints must not exceed 10000")
          Integer maxDataPoints) {
    log.info(
        "GET /api/timeline/{} with interval {}s and maxDataPoints {}",
        fileId,
        interval,
        maxDataPoints);

    List<TimelineDataDto> timeline =
        timelineService.getTimelineData(fileId, interval, maxDataPoints);
    return ResponseEntity.ok(timeline);
  }

  /**
   * Get timeline data for a specific time range
   *
   * @param fileId The file ID
   * @param start Start timestamp (ISO 8601 format)
   * @param end End timestamp (ISO 8601 format)
   * @param interval The time interval in seconds for binning (default: 60)
   * @param maxDataPoints Maximum number of data points to return (optional, uses config default if
   *     not provided)
   * @return List of timeline data points
   */
  @GetMapping("/{fileId}/range")
  public ResponseEntity<List<TimelineDataDto>> getTimelineRange(
      @PathVariable UUID fileId,
      @RequestParam String start,
      @RequestParam String end,
      @RequestParam(defaultValue = "60")
          @Min(value = 1, message = "interval must be at least 1 second")
          Integer interval,
      @RequestParam(required = false)
          @Min(value = 10, message = "maxDataPoints must be at least 10")
          @Max(value = 10000, message = "maxDataPoints must not exceed 10000")
          Integer maxDataPoints) {

    LocalDateTime startTime = LocalDateTime.parse(start);
    LocalDateTime endTime = LocalDateTime.parse(end);

    log.info(
        "GET /api/timeline/{}/range from {} to {} with interval {}s and maxDataPoints {}",
        fileId,
        startTime,
        endTime,
        interval,
        maxDataPoints);

    // Validate time range
    if (!startTime.isBefore(endTime)) {
      throw new IllegalArgumentException("start time must be before end time");
    }

    List<TimelineDataDto> timeline =
        timelineService.getTimelineDataForRange(
            fileId, startTime, endTime, interval, maxDataPoints);
    return ResponseEntity.ok(timeline);
  }
}
