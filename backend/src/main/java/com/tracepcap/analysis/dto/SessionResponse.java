package com.tracepcap.analysis.dto;

import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionResponse {

  /**
   * Detected application protocol: "HTTP", "SMTP", "FTP", "DNS", "TLS", or "RAW".
   * Derived from conversation metadata and stream content.
   */
  private String detectedProtocol;

  /** Ordered client/server data chunks representing the full reconstructed stream. */
  private List<Chunk> chunks;

  /**
   * Parsed HTTP request/response pairs. Only populated when {@code detectedProtocol} is "HTTP".
   */
  private List<HttpExchange> httpExchanges;

  /** True when the session exceeded the 1 MB size limit and was truncated. */
  private boolean truncated;

  private long totalClientBytes;
  private long totalServerBytes;

  /** Non-null when reconstruction failed; describes the reason. */
  private String errorMessage;

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Chunk {
    /** "CLIENT" or "SERVER" */
    private String direction;

    /**
     * Decoded content. Printable ASCII text is returned as-is; binary data is rendered as a
     * hex-dump string.
     */
    private String text;

    /** True when {@code text} is a hex dump rather than decoded ASCII. */
    private boolean binary;

    private long byteLength;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class HttpExchange {
    private HttpMessage request;
    private HttpMessage response;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class HttpMessage {
    /** E.g. "GET /path HTTP/1.1" or "HTTP/1.1 200 OK" */
    private String firstLine;

    /** HTTP headers (lowercased field names). */
    private Map<String, String> headers;

    /**
     * Decoded body text. {@code null} when the body is binary; in that case check
     * {@code bodyBinary} and {@code bodyLength}.
     */
    private String body;

    /** True when the body contained non-printable bytes (body field will be null). */
    private boolean bodyBinary;

    /** True when the body was gzip-encoded and successfully decompressed. */
    private boolean bodyDecompressed;

    /** True when the body was trimmed to the display limit. */
    private boolean bodyTruncated;

    /** Actual byte length of the body before any truncation. */
    private long bodyLength;
  }
}
