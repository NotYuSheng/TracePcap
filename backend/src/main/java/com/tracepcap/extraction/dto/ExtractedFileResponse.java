package com.tracepcap.extraction.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExtractedFileResponse {

  private UUID id;
  private UUID conversationId;
  private String filename;
  private String mimeType;
  private Long fileSize;
  private String sha256;
  private String extractionMethod;
  private String skippedReason;
  /** Where an HTTP download came from (http://host/path?query); null for carved files. */
  private String sourceUrl;
  private LocalDateTime createdAt;
}
