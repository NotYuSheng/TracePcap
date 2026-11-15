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

/** A client that asked for an address and was never answered: known by its MAC, not an address. */
@Entity
@Table(name = "dhcp_unanswered_clients")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DhcpUnansweredClientEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 50)
  private String mac;

  /** The name it asked under (DHCP option 12). */
  @Column(length = 255)
  private String hostname;

  @Column(name = "vendor_class", length = 255)
  private String vendorClass;

  /** The 802.1Q VLAN its requests were tagged with: which network it was asking on. */
  @Column(name = "vlan_id")
  private Integer vlanId;

  /** How many times it asked. */
  @Column(nullable = false)
  private Integer requests;

  @Column(name = "first_seen", nullable = false)
  private LocalDateTime firstSeen;

  @Column(name = "last_seen", nullable = false)
  private LocalDateTime lastSeen;
}
