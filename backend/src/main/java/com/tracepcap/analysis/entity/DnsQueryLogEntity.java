package com.tracepcap.analysis.entity;

import com.tracepcap.file.entity.FileEntity;
import jakarta.persistence.*;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * One aggregated DNS query/response row for a DNS-server host in a capture (#362).
 *
 * <p>Rows are aggregated per {@code (file, serverIp, queryName, queryType)}: repeated queries for
 * the same name collapse into a single row whose {@link #queryCount} reflects how many response
 * packets were seen. See {@code DnsQueryLogExtractor}.
 */
@Entity
@Table(
    name = "dns_query_log",
    indexes = {@Index(name = "idx_dns_query_log_file_server", columnList = "file_id, server_ip")})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DnsQueryLogEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id", nullable = false)
  private FileEntity file;

  /** IP of the DNS server that answered (the response packet's source IP). */
  @Column(name = "server_ip", nullable = false, length = 45)
  private String serverIp;

  /** Domain queried, e.g. "example.com". */
  @Column(name = "query_name", nullable = false, length = 255)
  private String queryName;

  /** DNS QTYPE name: A, AAAA, MX, PTR, TXT, … (null if unknown). */
  @Column(name = "query_type", length = 16)
  private String queryType;

  /** DNS RCODE name: NOERROR, NXDOMAIN, SERVFAIL, … (null if unknown). */
  @Column(name = "response_code", length = 16)
  private String responseCode;

  /** Comma-joined answer IPs (A/AAAA records); null/empty when the query returned no addresses. */
  @Column(name = "resolved_ips", columnDefinition = "text")
  private String resolvedIps;

  /** Number of response packets aggregated into this row. */
  @Column(name = "query_count", nullable = false)
  private int queryCount;

  /** True when the query resolved successfully (NOERROR with at least one answer). */
  @Column(name = "resolvable", nullable = false)
  private boolean resolvable;

  /** frame.number of the first response packet for this query — links the row to its packet. */
  @Column(name = "sample_frame")
  private Long sampleFrame;
}
