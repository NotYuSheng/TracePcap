package com.tracepcap.analysis.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One IPv6 router's advertisements in a capture (#1357): the router, the VLAN, the prefixes it gave
 * out and its DNS search domain. Its network's other half, the DHCPv6 leases, are {@link
 * DhcpLeaseEntity} rows.
 */
@Entity
@Table(name = "router_adverts")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RouterAdvertEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "router_mac", nullable = false, length = 50)
  private String routerMac;

  /** Its source address, link-local as RFC 4861 requires. */
  @Column(name = "router_ip", length = 45)
  private String routerIp;

  @Column(name = "vlan_id")
  private Integer vlanId;

  /** The prefixes it advertised, as CIDRs ({@code fd00:a::/64}). */
  @Column(name = "prefixes", columnDefinition = "text[]", nullable = false)
  private String[] prefixes;

  @Column(length = 255)
  private String domain;

  @Column(name = "first_seen", nullable = false)
  private LocalDateTime firstSeen;

  @Column(name = "last_seen", nullable = false)
  private LocalDateTime lastSeen;
}
