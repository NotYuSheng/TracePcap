package com.tracepcap.analysis.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Suricata's counters for one capture's run (#1268). See V81. */
@Entity
@Table(name = "capture_stats")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaptureStatsEntity {
  @Id
  @Column(name = "file_id")
  private UUID fileId;

  private Long packets;

  @Column(name = "invalid_packets")
  private Long invalidPackets;

  @Column(name = "tcp_sessions")
  private Long tcpSessions;

  @Column(name = "reassembly_gaps")
  private Long reassemblyGaps;

  @Column(name = "stream_depth_reached")
  private Long streamDepthReached;

  @Column(name = "memcap_drops")
  private Long memcapDrops;

  @Column(name = "recorded_at", nullable = false)
  @Builder.Default
  private LocalDateTime recordedAt = LocalDateTime.now();
}
