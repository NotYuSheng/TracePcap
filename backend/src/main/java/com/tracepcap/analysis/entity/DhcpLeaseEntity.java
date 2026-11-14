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

  @Column(name = "first_seen", nullable = false)
  private LocalDateTime firstSeen;

  @Column(name = "last_seen", nullable = false)
  private LocalDateTime lastSeen;
}
