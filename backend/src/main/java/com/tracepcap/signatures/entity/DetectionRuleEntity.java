package com.tracepcap.signatures.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** A custom detection rule (#925). See V50. */
@Entity
@Table(name = "detection_rules")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DetectionRuleEntity {

  public enum Scope {
    GLOBAL,
    NETWORK,
    CAPTURE
  }

  @Id private UUID id;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private Scope scope;

  @Column(name = "network_id")
  private UUID networkId;

  @Column(name = "file_id")
  private UUID fileId;

  @Column(nullable = false, length = 200)
  private String name;

  private String description;

  @Column(nullable = false, length = 20)
  private String severity;

  @Column(nullable = false)
  private boolean enabled;

  /** The YAML {@code match} block: ip, cidr, srcPort, dstPort, ja3, hostname, app, protocol. */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "match_criteria", columnDefinition = "jsonb", nullable = false)
  private Map<String, Object> matchCriteria;

  /** {@code [{ascii: ...} | {hex: ...}]} */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "payload_contains", columnDefinition = "jsonb", nullable = false)
  private List<Map<String, Object>> payloadContains;

  /** {@code [{pattern: ..., case_insensitive: bool}]} */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "payload_regex", columnDefinition = "jsonb", nullable = false)
  private List<Map<String, Object>> payloadRegex;

  @Column(name = "match_all", nullable = false)
  private boolean matchAll;

  /** Legacy override of the matched hosts' device type; #926 replaces it. Not editable. */
  @Column(name = "device_type", length = 100)
  private String deviceType;

  /** The rule this one was promoted from (#925 phase 3), if any. */
  @Column(name = "promoted_from")
  private UUID promotedFrom;

  /** Bumped on every edit, so matches can later be checked against the version they came from. */
  @Column(nullable = false)
  private int version;

  @Column(name = "created_at", nullable = false)
  private LocalDateTime createdAt;

  @Column(name = "created_by", nullable = false)
  private String createdBy;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Column(name = "updated_by", nullable = false)
  private String updatedBy;
}
