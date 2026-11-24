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

/** One Suricata protocol anomaly on a conversation (#1268). See V81. */
@Entity
@Table(name = "suricata_anomalies")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SuricataAnomalyEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "conversation_id", nullable = false)
  private UUID conversationId;

  @Column(name = "anomaly_time")
  private LocalDateTime time;

  @Column(name = "src_ip")
  private String srcIp;

  @Column(name = "dst_ip")
  private String dstIp;

  @Column(name = "anomaly_type")
  private String type;

  private String layer;

  @Column(name = "app_proto")
  private String appProto;

  @Column(nullable = false)
  private String event;
}
