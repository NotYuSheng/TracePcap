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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** One Suricata alert as logged (#1265). See V80. */
@Entity
@Table(name = "ids_alerts")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdsAlertEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "conversation_id", nullable = false)
  private UUID conversationId;

  @Column(name = "alert_time")
  private LocalDateTime alertTime;

  @Column(name = "src_ip")
  private String srcIp;

  @Column(name = "src_port")
  private Integer srcPort;

  @Column(name = "dst_ip")
  private String dstIp;

  @Column(name = "dst_port")
  private Integer dstPort;

  @Column(nullable = false)
  private long sid;

  private Integer gid;
  private Integer rev;

  @Column(nullable = false, columnDefinition = "text")
  private String signature;

  private String category;
  private Integer severity;

  @Column(name = "signature_severity")
  private String signatureSeverity;

  private String confidence;

  @Column(name = "attack_target")
  private String attackTarget;

  /** The rule's metadata block as Suricata logged it: key → list of values. */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(columnDefinition = "jsonb")
  private java.util.Map<String, java.util.List<String>> metadata;

  @Column(name = "http_method")
  private String httpMethod;

  @Column(name = "http_host")
  private String httpHost;

  @Column(name = "http_url", columnDefinition = "text")
  private String httpUrl;

  @Column(name = "http_user_agent", columnDefinition = "text")
  private String httpUserAgent;

  @Column(name = "http_status")
  private Integer httpStatus;
}
