package com.lanturn.analysis.dto;

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
   * Detected application protocol: "HTTP", "SMTP", "FTP", "DNS", "TLS", or "RAW". Derived from
   * conversation metadata and stream content.
   */
  private String detectedProtocol;

  /** Ordered client/server data chunks representing the full reconstructed stream. */
  private List<Chunk> chunks;

  /** Parsed HTTP request/response pairs. Only populated when {@code detectedProtocol} is "HTTP". */
  private List<HttpExchange> httpExchanges;

  /** Decoded STUN messages. Only populated when {@code detectedProtocol} is "STUN". */
  private List<StunMessage> stunMessages;

  /**
   * Media metadata detected in the payload (RTP, MP4, WebM, etc.). Null when no known media
   * signature was found.
   */
  private MediaInfo mediaInfo;

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
  public static class StunMessage {
    /** "CLIENT" or "SERVER" — which side sent this STUN message. */
    private String direction;

    /** E.g. "Binding Request", "Binding Success Response", "Allocate Request". */
    private String messageType;

    /** STUN message class: "Request", "Indication", "Success Response", "Error Response". */
    private String messageClass;

    /** Hex transaction ID (12 bytes = 24 hex chars). */
    private String transactionId;

    /** Decoded STUN attributes (attribute type name → decoded value). */
    private Map<String, String> attributes;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class MediaInfo {
    /**
     * High-level media category: "VIDEO", "AUDIO", "IMAGE", or "MEDIA" (when ambiguous).
     */
    private String mediaType;

    /**
     * Container/protocol format, e.g. "RTP", "MP4", "WebM", "Ogg", "JPEG", "PNG", "WebP", "AAC".
     */
    private String containerFormat;

    /**
     * Codec hint when determinable from the container header, e.g. "H.264", "VP8", "Opus",
     * "AAC". Null when not determinable without full demuxing.
     */
    private String codec;

    /** Image width in pixels (images only). Null when not applicable or not parseable. */
    private Integer width;

    /** Image height in pixels (images only). Null when not applicable or not parseable. */
    private Integer height;

    /** Audio sample rate in Hz (audio streams only). Null when not applicable. */
    private Integer sampleRate;

    /** Number of detected independent streams (e.g. RTP SSRCs). */
    private Integer streamCount;
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
     * Decoded body text. {@code null} when the body is binary; in that case check {@code
     * bodyBinary} and {@code bodyLength}.
     */
    private String body;

    /** True when the body contained non-printable bytes (body field will be null). */
    private boolean bodyBinary;

    /** True when the body was content-encoded and successfully decompressed. */
    private boolean bodyDecompressed;

    /**
     * The original Content-Encoding value (e.g. "gzip", "deflate", "br") when decompression was
     * applied, otherwise null.
     */
    private String bodyEncoding;

    /** Compressed byte length before decompression; 0 when not decompressed. */
    private long bodyCompressedLength;

    /** True when the body was trimmed to the display limit. */
    private boolean bodyTruncated;

    /** Actual byte length of the body before any truncation. */
    private long bodyLength;
  }
}
