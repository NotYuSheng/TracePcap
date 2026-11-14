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
 * One TTL a source address sent with, and when (#918 slice 2). Lets each occupancy of an address
 * get the TTL its own device sent, rather than the address's first-seen one.
 */
@Entity
@Table(name = "host_ttl_windows")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HostTtlWindowEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  @Column(nullable = false)
  private Integer ttl;

  @Column(name = "first_seen", nullable = false)
  private LocalDateTime firstSeen;

  @Column(name = "last_seen", nullable = false)
  private LocalDateTime lastSeen;

  @Column(nullable = false)
  private long packets;

  /** The MAC the TTL was sent from (#462); null on rows from before it was recorded. */
  @Column(length = 50)
  private String mac;
}
