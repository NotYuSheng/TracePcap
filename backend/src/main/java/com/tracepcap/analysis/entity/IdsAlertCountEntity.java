package com.tracepcap.analysis.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** How many alerts fired on one conversation, and how many records were kept (#1284). See V84. */
@Entity
@Table(name = "ids_alert_counts")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdsAlertCountEntity {
  @Id
  @Column(name = "conversation_id")
  private UUID conversationId;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "src_ip", length = 45)
  private String srcIp;

  @Column(name = "dst_ip", length = 45)
  private String dstIp;

  @Column(nullable = false)
  private int total;

  @Column(nullable = false)
  private int kept;
}
