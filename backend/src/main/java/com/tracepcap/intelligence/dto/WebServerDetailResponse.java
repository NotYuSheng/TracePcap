package com.tracepcap.intelligence.dto;

import java.time.LocalDateTime;
import java.util.List;
import lombok.Builder;
import lombok.Data;

/**
 * Full detail for one web/API-server host: its HTTP endpoints (cleartext only) plus server-level
 * detail (Server software, content types, TLS metadata) and the enumeration verdict.
 */
@Data
@Builder
public class WebServerDetailResponse {
  private String serverIp;
  private String hostname;
  private boolean api; // true = classified API server, false = plain web server

  private long totalRequests;
  private long successCount; // 2xx/3xx
  private long clientErrorCount; // 4xx
  private long serverErrorCount; // 5xx
  private double clientErrorRatio; // 4xx share of all requests (0–1)
  private boolean suspicious; // high 4xx ratio → endpoint enumeration / scanning

  private String serverSoftware; // Server header, e.g. "nginx/1.18.0"
  private List<String> contentTypes; // distinct response content types served

  private TlsInfo tls; // null when no TLS observed for this host

  private List<HttpEndpointDto> endpoints;

  /** One aggregated endpoint row. */
  @Data
  @Builder
  public static class HttpEndpointDto {
    private String method;
    private String path;
    private Integer topStatus;
    private int requestCount;
    private int successCount;
    private int clientErrorCount;
    private int serverErrorCount;
    private String contentType;
    /** frame.number of the first request/response packet (for "view packet"); null if unknown. */
    private Integer requestFrame;
    private Integer responseFrame;
  }

  /** TLS metadata observed for the server, reconstructed from conversation enrichment. */
  @Data
  @Builder
  public static class TlsInfo {
    private String subject; // certificate subject
    private String issuer; // certificate issuer
    private String ja3s; // server JA3S fingerprint
    private List<String> sniNames; // SNI hostnames clients requested from this server
    private LocalDateTime notBefore;
    private LocalDateTime notAfter;
  }
}
