package com.tracepcap.analysis.entity;

import com.tracepcap.file.entity.FileEntity;
import jakarta.persistence.*;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(
    name = "host_classifications",
    indexes = {@Index(name = "idx_host_class_file_id", columnList = "file_id")})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HostClassificationEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id", nullable = false)
  private FileEntity file;

  /** IP address of the classified host. */
  @Column(name = "ip", nullable = false, length = 45)
  private String ip;

  /** First-seen Ethernet MAC address (may be null for remote/tunneled hosts). */
  @Column(name = "mac", length = 17)
  private String mac;

  /** OUI vendor name derived from the MAC address (e.g. "Apple", "Cisco"). */
  @Column(name = "manufacturer", length = 100)
  private String manufacturer;

  /**
   * Passively-discovered hostname for this host (e.g. "Johns-MacBook.local", "DESKTOP-AB12"). Null
   * when no name was observed in the capture.
   */
  @Column(name = "hostname", length = 255)
  private String hostname;

  /**
   * How {@link #hostname} was discovered. One of: {@code reverse_dns}, {@code mdns}, {@code nbns},
   * {@code dhcp}, {@code manual}. Null when no hostname is set.
   */
  @Column(name = "hostname_source", length = 20)
  private String hostnameSource;

  /** First-seen IP TTL value (may be null for non-IP traffic). */
  @Column(name = "ttl")
  private Integer ttl;

  /**
   * Classified device type. One of: ROUTER, MOBILE, LAPTOP_DESKTOP, SERVER, IOT, UNKNOWN, or a
   * custom string set by a YAML device_type override.
   */
  @Column(name = "device_type", nullable = false, length = 50)
  private String deviceType;

  /** Classification confidence from 0–100. Higher = more signals agreed. */
  @Column(name = "confidence", nullable = false)
  private int confidence;

  /**
   * True when this host acted as a DNS server whose share of NXDOMAIN responses exceeded the
   * configured threshold — a signal of DNS tunnelling or a domain-generation algorithm. Set during
   * analysis from {@code DnsQueryLogExtractor}.
   */
  @Column(name = "dns_suspicious", nullable = false)
  private boolean dnsSuspicious;

  /**
   * Comma-joined service roles this host was detected serving (e.g. {@code "dns"}). Drives the
   * device classification and the per-role activity tabs in the node modal. Null when none.
   */
  @Column(name = "service_roles", columnDefinition = "text")
  private String serviceRoles;
}
