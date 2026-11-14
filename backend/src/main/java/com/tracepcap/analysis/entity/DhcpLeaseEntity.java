package com.tracepcap.analysis.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** A DHCP lease seen in a capture: an address handed to a client MAC, first and last seen (#918). */
@Entity
@Table(name = "dhcp_leases")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DhcpLeaseEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  @Column(nullable = false, length = 50)
  private String mac;

  @Column(length = 255)
  private String hostname;

  /** The options the client asked for, in order (DHCP option 55), comma-joined (#918 slice 4b). */
  @Column(length = 255)
  private String fingerprint;

  /** The client's vendor class (DHCP option 60), e.g. "android-dhcp-14". */
  @Column(name = "vendor_class", length = 255)
  private String vendorClass;

  // ── The network the lease came from (#462), from the server's ACK ─────────────

  @Column(name = "server_mac", length = 50)
  private String serverMac;

  /** DHCP option 54. */
  @Column(name = "server_id", length = 45)
  private String serverId;

  /** DHCP option 3. */
  @Column(length = 45)
  private String router;

  /** DHCP option 15. */
  @Column(length = 255)
  private String domain;

  /** DHCP option 51. */
  @Column(name = "lease_seconds")
  private Long leaseSeconds;

  /** DHCP option 1. */
  @Column(name = "subnet_mask", length = 45)
  private String subnetMask;

  /** The 802.1Q VLAN the ACK was tagged with. */
  @Column(name = "vlan_id")
  private Integer vlanId;

  @Column(name = "first_seen", nullable = false)
  private LocalDateTime firstSeen;

  @Column(name = "last_seen", nullable = false)
  private LocalDateTime lastSeen;
}
