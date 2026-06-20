package com.tracepcap.intelligence.dto;

import java.util.List;
import lombok.Builder;
import lombok.Data;

/**
 * Full DNS query log for one DNS-server host (#362): the per-domain rows plus a roll-up summary and
 * the suspicious verdict driving the UI alert banner.
 */
@Data
@Builder
public class DnsQueryLogResponse {
  private String serverIp;
  private String hostname;

  /** Distinct queries that resolved successfully. */
  private long resolvedCount;

  /** Distinct queries that failed to resolve. */
  private long failedCount;

  /** NXDOMAIN share of all distinct queries (0–1). */
  private double nxdomainRatio;

  /** True when {@link #nxdomainRatio} crosses the configured threshold over enough queries. */
  private boolean suspicious;

  private List<DnsQueryEntryDto> entries;

  /** One aggregated query row: a domain queried against this server and how it resolved. */
  @Data
  @Builder
  public static class DnsQueryEntryDto {
    private String queryName;
    private String queryType;
    private String responseCode;
    private List<String> resolvedIps;
    private int queryCount;
    private boolean resolvable;
    /** frame.number of the response packet this row came from (for "view packet"); null if unknown. */
    private Long frame;
  }
}
