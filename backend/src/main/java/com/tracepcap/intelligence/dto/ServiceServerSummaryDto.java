package com.tracepcap.intelligence.dto;

import lombok.Builder;
import lombok.Data;

/**
 * Role-agnostic summary of a host acting as a service server, for the Network Intelligence
 * per-service cards. DNS populates it today (#362); future roles (e.g. web/API servers) reuse the
 * same shape — {@code okCount}/{@code failedCount}/{@code anomalyRatio} are interpreted per role.
 */
@Data
@Builder
public class ServiceServerSummaryDto {
  /** IP of the server host. */
  private String serverIp;

  /** Passively-discovered hostname for the server, if known. */
  private String hostname;

  /** Service role, e.g. "dns". */
  private String role;

  /** Total distinct requests observed (for DNS: distinct query name/type rows). */
  private long totalRequests;

  /** Requests that succeeded (for DNS: resolvable queries). */
  private long okCount;

  /** Requests that failed (for DNS: unresolvable queries). */
  private long failedCount;

  /** Anomaly ratio used for the suspicious flag (for DNS: NXDOMAIN share of requests). */
  private double anomalyRatio;

  /** True when this server's anomaly ratio crosses the configured threshold. */
  private boolean suspicious;
}
