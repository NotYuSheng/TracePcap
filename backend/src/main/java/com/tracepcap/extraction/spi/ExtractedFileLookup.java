package com.tracepcap.extraction.spi;

import java.util.List;
import java.util.UUID;

/** The files extracted from a capture, for other modules (the knowledge layer's download answers). */
public interface ExtractedFileLookup {

  /**
   * One extracted file.
   *
   * @param method how it was found: {@code tshark_http} is a real HTTP transfer, reassembled;
   *     {@code magic_bytes} is a file signature carved from a raw stream, which can be a false hit
   * @param skipped true when it was recorded but not stored (too large, a limit hit)
   */
  record ExtractedFileFacts(
      UUID conversationId,
      String filename,
      String mimeType,
      Long size,
      String sha256,
      String method,
      boolean skipped) {

    /** A transfer the protocol itself delimited, not a guess from bytes that looked like a file. */
    public boolean realTransfer() {
      return method != null && !"magic_bytes".equals(method);
    }
  }

  List<ExtractedFileFacts> extractedFiles(UUID fileId);
}
