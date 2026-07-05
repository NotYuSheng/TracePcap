package com.tracepcap.analysis.entity;

import jakarta.persistence.*;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * One distinct source MAC observed for an IP within a capture (#461). Unlike {@code
 * host_classifications} (one row per {@code (file_id, ip)}), multiple rows can share an IP — that is
 * exactly the overlap signal: two devices claiming the same IP in one capture.
 */
@Entity
@Table(name = "ip_mac_observations")
@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IpMacObservationEntity {

  @EqualsAndHashCode.Include
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  @Column(nullable = false, length = 17)
  private String mac;
}
