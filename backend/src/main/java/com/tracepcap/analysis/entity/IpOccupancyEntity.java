package com.tracepcap.analysis.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One device holding one address for part of a capture (#918 item 3). Derived: rows exist only for
 * addresses with more than one occupancy, and cover [startsAt, endsAt) (null = capture start/end).
 */
@Entity
@Table(name = "ip_occupancies")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IpOccupancyEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  /** Reserved for #462 (overlapping ranges at two sites); unused until then. */
  @Column(name = "segment_key", length = 64)
  private String segmentKey;

  @Column(nullable = false)
  private Integer idx;

  @Column(length = 50)
  private String mac;

  @Column(length = 255)
  private String hostname;

  @Column(name = "starts_at")
  private LocalDateTime startsAt;

  @Column(name = "ends_at")
  private LocalDateTime endsAt;

  /** What started this occupancy: arp, dhcp or manual (null for the first). */
  @Column(name = "start_source", length = 10)
  private String startSource;

  @Column(name = "start_evidence", columnDefinition = "TEXT")
  private String startEvidence;
}
