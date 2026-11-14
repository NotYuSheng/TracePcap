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

  /**
   * The device's key ({@link com.tracepcap.analysis.spi.DeviceKeys}): the bare IP for the first,
   * ip@start for a later one in time, ip~network for one on another network (#462).
   */
  @Column(name = "device_key", length = 255)
  private String deviceKey;

  /** This row's key, worked out for rows from before it was stored. */
  public String key() {
    return deviceKey != null ? deviceKey : com.tracepcap.analysis.spi.DeviceKeys.key(ip, startsAt);
  }

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

  // ── This occupancy's own classification (#918 slice 2) ──────────────────────
  // Worked out from the traffic in [startsAt, endsAt) only. Null until classified.

  @Column(name = "device_type", length = 50)
  private String deviceType;

  private Integer confidence;

  @Column(name = "winner_score")
  private Integer winnerScore;

  @Column(name = "winner_reasons", columnDefinition = "TEXT")
  private String winnerReasons;

  @Column(name = "runner_up_type", length = 50)
  private String runnerUpType;

  @Column(name = "runner_up_score")
  private Integer runnerUpScore;

  @Column(name = "runner_up_reasons", columnDefinition = "TEXT")
  private String runnerUpReasons;

  @Column(length = 255)
  private String manufacturer;

  private Integer ttl;

  @Column(name = "logged_in_user", length = 255)
  private String loggedInUser;

  @Column(name = "conversation_count")
  private Long conversationCount;
}
