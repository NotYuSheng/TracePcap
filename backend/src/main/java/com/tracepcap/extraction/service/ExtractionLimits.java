package com.tracepcap.extraction.service;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Runtime-tunable limits for the file extraction pipeline.
 *
 * <p>Each value defaults to its historical compile-time constant and can be overridden via an
 * environment variable (wired through {@code application.yml}) without rebuilding the image. Shared
 * by {@link FileExtractionService} (enforcement) and the extractions controller (surfacing the
 * configured values in UI warnings).
 */
@Component
@Getter
public class ExtractionLimits {

  /** Maximum embedded files extracted per raw TCP/UDP stream. */
  @Value("${tracepcap.extraction.max-matches-per-stream:20}")
  private int maxMatchesPerStream;

  /** Maximum number of non-HTTP conversations scanned for embedded files per PCAP. */
  @Value("${tracepcap.extraction.max-stream-conversations:50}")
  private int maxStreamConversations;

  /** Maximum size, in megabytes, of a single extracted file stored in MinIO. */
  @Value("${tracepcap.extraction.max-file-size-mb:50}")
  private int maxFileSizeMb;

  /** Convenience accessor returning the per-file size limit in bytes. */
  public long maxFileSizeBytes() {
    return (long) maxFileSizeMb * 1024 * 1024;
  }

  /**
   * Fail fast on misconfiguration so a bad value is caught at startup rather than crashing
   * mid-analysis. {@code maxMatchesPerStream} must be at least 1 (0 would still extract one file
   * yet report the cap as hit). The other two may be 0 — meaning "scan no raw streams" / "store no
   * extracted files" respectively — but never negative (which would break {@code subList}/{@code
   * limit} and size comparisons downstream).
   */
  @PostConstruct
  void validate() {
    if (maxMatchesPerStream < 1 || maxStreamConversations < 0 || maxFileSizeMb < 0) {
      throw new IllegalStateException(
          "Invalid extraction limits (maxMatchesPerStream must be >= 1; the others >= 0): "
              + "maxMatchesPerStream="
              + maxMatchesPerStream
              + ", maxStreamConversations="
              + maxStreamConversations
              + ", maxFileSizeMb="
              + maxFileSizeMb);
    }
  }
}
