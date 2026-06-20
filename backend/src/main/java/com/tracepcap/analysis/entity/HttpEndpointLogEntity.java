package com.tracepcap.analysis.entity;

import com.tracepcap.file.entity.FileEntity;
import jakarta.persistence.*;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * One aggregated HTTP endpoint row for a web/API-server host in a capture — the web/API equivalent of
 * {@link DnsQueryLogEntity}. Rows are aggregated per {@code (file, serverIp, method, path)}. See
 * {@code WebServerLogExtractor}.
 */
@Entity
@Table(
    name = "http_endpoint_log",
    indexes = {
      @Index(name = "idx_http_endpoint_log_file_server", columnList = "file_id, server_ip")
    })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HttpEndpointLogEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id", nullable = false)
  private FileEntity file;

  /** IP of the host that served the response. */
  @Column(name = "server_ip", nullable = false, length = 45)
  private String serverIp;

  /** HTTP request method (GET, POST, …); null if it couldn't be matched. */
  @Column(name = "method", length = 16)
  private String method;

  /** Request URI / endpoint path. */
  @Column(name = "path", nullable = false, columnDefinition = "text")
  private String path;

  /** Responses aggregated into this row. */
  @Column(name = "request_count", nullable = false)
  private int requestCount;

  /** 2xx/3xx responses. */
  @Column(name = "success_count", nullable = false)
  private int successCount;

  /** 4xx responses (enumeration / auth failures / bad requests). */
  @Column(name = "client_error_count", nullable = false)
  private int clientErrorCount;

  /** 5xx responses. */
  @Column(name = "server_error_count", nullable = false)
  private int serverErrorCount;

  /** Most-frequent status code, for display. */
  @Column(name = "top_status")
  private Integer topStatus;

  /** Representative response Content-Type (e.g. application/json, text/html). */
  @Column(name = "content_type", length = 255)
  private String contentType;

  /** Response Server header (e.g. "nginx/1.18.0"); null when not sent. */
  @Column(name = "server_software", length = 255)
  private String serverSoftware;

  /** frame.number of the first request packet for this endpoint — links to the sent packet. */
  @Column(name = "request_frame")
  private Integer requestFrame;

  /** frame.number of the first response packet for this endpoint — links to the response packet. */
  @Column(name = "response_frame")
  private Integer responseFrame;
}
