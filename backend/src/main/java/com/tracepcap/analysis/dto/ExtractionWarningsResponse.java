package com.tracepcap.analysis.dto;

import java.util.List;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Reports which configurable file-extraction limits were hit while processing a PCAP, with enough
 * detail (specific streams and files) for the UI to point users at what was truncated, alongside the
 * limit values in effect.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExtractionWarningsResponse {

  /** Conversation IDs whose raw stream hit the per-stream file cap; more files may exist. */
  private List<UUID> matchLimitConversationIds;

  /** Total non-HTTP file-bearing streams that were not scanned because of the conversation cap. */
  private int conversationLimitSkippedCount;

  /** Conversation IDs (capped) of the non-HTTP streams that were skipped. */
  private List<UUID> conversationLimitSkippedIds;

  /** Files detected but not stored because they exceeded the per-file size limit. */
  private List<SkippedFile> sizeLimitFiles;

  /** Configured maximum files extracted per raw stream. */
  private int maxMatchesPerStream;

  /** Configured maximum non-HTTP streams scanned per PCAP. */
  private int maxStreamConversations;

  /** Configured maximum size, in MB, of a single extracted file. */
  private int maxFileSizeMb;

  /** A single file that was detected but skipped for exceeding the size limit. */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class SkippedFile {
    private UUID id;
    private UUID conversationId;
    private String filename;
    private Long fileSize;
  }
}
