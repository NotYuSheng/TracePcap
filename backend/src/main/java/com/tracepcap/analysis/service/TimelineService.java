package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.TimelineDataDto;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class TimelineService {

  private final FileRepository fileRepository;
  private final ConversationRepository conversationRepository;
  private final com.tracepcap.config.AnalysisProperties analysisProperties;

  /**
   * Get timeline data for a file with specified interval
   *
   * @param fileId The file ID
   * @param interval Time interval in seconds for binning
   * @param maxDataPoints Maximum number of data points (null to use config default)
   * @return List of timeline data points
   */
  @Transactional(readOnly = true)
  public List<TimelineDataDto> getTimelineData(
      UUID fileId, Integer interval, Integer maxDataPoints) {
    log.info("Generating timeline data for file {} with {}s intervals", fileId, interval);

    // Verify file exists
    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    // Get all conversations (which represent traffic flows)
    List<ConversationEntity> conversations = conversationRepository.findByFileId(fileId);

    if (conversations.isEmpty()) {
      log.warn("No conversations found for file {}", fileId);
      return new ArrayList<>();
    }

    // Determine time range from file metadata or conversations
    LocalDateTime startTime = file.getStartTime();
    LocalDateTime endTime = file.getEndTime();

    if (startTime == null || endTime == null) {
      // Fallback to conversation times
      startTime =
          conversations.stream()
              .map(ConversationEntity::getStartTime)
              .min(LocalDateTime::compareTo)
              .orElse(LocalDateTime.now());
      endTime =
          conversations.stream()
              .map(ConversationEntity::getEndTime)
              .max(LocalDateTime::compareTo)
              .orElse(LocalDateTime.now());
    }

    // Calculate optimal interval respecting maxDataPoints limit
    Integer optimalInterval = calculateOptimalInterval(startTime, endTime, interval, maxDataPoints);

    return generateTimelineBins(conversations, startTime, endTime, optimalInterval);
  }

  /**
   * Get timeline data for a specific time range
   *
   * @param fileId The file ID
   * @param startTime Start of time range
   * @param endTime End of time range
   * @param interval Time interval in seconds for binning
   * @param maxDataPoints Maximum number of data points (null to use config default)
   * @return List of timeline data points
   */
  @Transactional(readOnly = true)
  public List<TimelineDataDto> getTimelineDataForRange(
      UUID fileId,
      LocalDateTime startTime,
      LocalDateTime endTime,
      Integer interval,
      Integer maxDataPoints) {
    log.info(
        "Generating timeline data for file {} from {} to {} with {}s intervals",
        fileId,
        startTime,
        endTime,
        interval);

    // Verify file exists
    fileRepository
        .findById(fileId)
        .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    // Get conversations
    List<ConversationEntity> conversations = conversationRepository.findByFileId(fileId);

    // Filter conversations that overlap with the requested time range
    List<ConversationEntity> filteredConversations =
        conversations.stream()
            .filter(
                conv ->
                    !conv.getEndTime().isBefore(startTime) && !conv.getStartTime().isAfter(endTime))
            .collect(Collectors.toList());

    // Calculate optimal interval respecting maxDataPoints limit
    Integer optimalInterval = calculateOptimalInterval(startTime, endTime, interval, maxDataPoints);

    return generateTimelineBins(filteredConversations, startTime, endTime, optimalInterval);
  }

  /**
   * Generate timeline bins by aggregating conversation data into time intervals
   *
   * @param conversations List of conversations
   * @param startTime Start time
   * @param endTime End time
   * @param intervalSecs Interval in seconds
   * @return List of timeline data points
   */
  private List<TimelineDataDto> generateTimelineBins(
      List<ConversationEntity> conversations,
      LocalDateTime startTime,
      LocalDateTime endTime,
      Integer intervalSecs) {

    // Create time bins
    List<LocalDateTime> binStarts = new ArrayList<>();
    LocalDateTime currentTime = startTime;
    while (currentTime.isBefore(endTime)) {
      binStarts.add(currentTime);
      currentTime = currentTime.plusSeconds(intervalSecs);
    }

    // Create a map to store data for each bin
    Map<LocalDateTime, TimelineBinData> bins = new LinkedHashMap<>();
    for (LocalDateTime binStart : binStarts) {
      bins.put(binStart, new TimelineBinData());
    }

    // Distribute conversations into bins
    for (ConversationEntity conv : conversations) {
      LocalDateTime convStart = conv.getStartTime();
      LocalDateTime convEnd = conv.getEndTime();

      // For simplicity, we'll attribute the entire conversation to its start time bin
      // A more sophisticated approach would distribute across multiple bins
      LocalDateTime binStart = findBinForTimestamp(convStart, binStarts, intervalSecs);

      if (binStart != null && bins.containsKey(binStart)) {
        TimelineBinData bin = bins.get(binStart);
        bin.packetCount += conv.getPacketCount();
        bin.bytes += conv.getTotalBytes();

        // Aggregate by protocol
        String protocol = conv.getProtocol();
        bin.protocols.merge(protocol, conv.getPacketCount(), Long::sum);
      }
    }

    // Convert bins to DTOs
    return bins.entrySet().stream()
        .map(
            entry ->
                TimelineDataDto.builder()
                    .timestamp(entry.getKey())
                    .packetCount(entry.getValue().packetCount)
                    .bytes(entry.getValue().bytes)
                    .protocols(entry.getValue().protocols)
                    .build())
        .collect(Collectors.toList());
  }

  /**
   * Find the appropriate bin for a given timestamp
   *
   * @param timestamp The timestamp to bin
   * @param binStarts List of bin start times
   * @param intervalSecs Interval size in seconds
   * @return The bin start time, or null if not found
   */
  private LocalDateTime findBinForTimestamp(
      LocalDateTime timestamp, List<LocalDateTime> binStarts, Integer intervalSecs) {
    for (int i = 0; i < binStarts.size(); i++) {
      LocalDateTime binStart = binStarts.get(i);
      LocalDateTime binEnd = binStart.plusSeconds(intervalSecs);

      if (!timestamp.isBefore(binStart) && timestamp.isBefore(binEnd)) {
        return binStart;
      }
    }

    // If timestamp is after all bins, return the last bin
    if (!binStarts.isEmpty() && !timestamp.isBefore(binStarts.get(binStarts.size() - 1))) {
      return binStarts.get(binStarts.size() - 1);
    }

    return null;
  }

  /**
   * Calculate optimal interval to respect maxDataPoints limit
   *
   * @param start Start time
   * @param end End time
   * @param requestedInterval Requested interval in seconds
   * @param maxDataPoints Maximum number of data points (null to use config default)
   * @return Optimal interval in seconds
   */
  private Integer calculateOptimalInterval(
      LocalDateTime start, LocalDateTime end, Integer requestedInterval, Integer maxDataPoints) {
    // Use config default if not provided
    int limit =
        maxDataPoints != null ? maxDataPoints : analysisProperties.getMaxTimelineDataPoints();

    // If auto-adjust is disabled, return requested interval
    if (!analysisProperties.isAutoAdjustInterval()) {
      return requestedInterval;
    }

    // Calculate duration and expected bin count
    long durationSeconds = ChronoUnit.SECONDS.between(start, end);
    long expectedBins = durationSeconds / requestedInterval;

    // If within limit, no adjustment needed
    if (expectedBins <= limit) {
      return requestedInterval;
    }

    // Calculate minimum interval to stay under limit
    int adjustedInterval = (int) Math.ceil((double) durationSeconds / limit);

    // Enforce minimum interval constraint
    adjustedInterval = Math.max(adjustedInterval, analysisProperties.getMinTimelineInterval());

    log.info(
        "Timeline auto-adjusted: duration={}s, requestedInterval={}s, "
            + "adjustedInterval={}s, expectedBins={}, limit={}",
        durationSeconds,
        requestedInterval,
        adjustedInterval,
        expectedBins,
        limit);

    return adjustedInterval;
  }

  /** Internal class to accumulate data for a time bin */
  private static class TimelineBinData {
    Long packetCount = 0L;
    Long bytes = 0L;
    Map<String, Long> protocols = new HashMap<>();
  }
}
