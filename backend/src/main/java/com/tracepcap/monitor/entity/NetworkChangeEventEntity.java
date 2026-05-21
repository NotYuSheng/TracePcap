package com.lanturn.monitor.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "network_change_events")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkChangeEventEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "network_id", nullable = false)
  private NetworkEntity network;

  /** Null when comparing the first snapshot against a manual baseline. */
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "from_snapshot_id")
  private NetworkSnapshotEntity fromSnapshot;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "to_snapshot_id", nullable = false)
  private NetworkSnapshotEntity toSnapshot;

  @Enumerated(EnumType.STRING)
  @Column(name = "change_type", nullable = false, length = 50)
  private ChangeType changeType;

  @Enumerated(EnumType.STRING)
  @Column(name = "entity_type", nullable = false, length = 50)
  private EntityType entityType;

  @Column(name = "entity_key", nullable = false, length = 255)
  private String entityKey;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "old_value", columnDefinition = "jsonb")
  private Map<String, Object> oldValue;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "new_value", columnDefinition = "jsonb")
  private Map<String, Object> newValue;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private Severity severity;

  @Column(name = "detected_at", nullable = false)
  private LocalDateTime detectedAt;

  @Builder.Default
  @Column(nullable = false)
  private boolean reviewed = false;

  @Column(columnDefinition = "text")
  private String notes;

  public enum ChangeType {
    MAC_ADDED,
    MAC_REMOVED,
    IP_MAC_DRIFT,
    ASN_CHANGE,
    GATEWAY_CHANGE,
    PROTOCOL_ADDED,
    PROTOCOL_REMOVED,
    APP_ADDED,
    APP_REMOVED,
    VPN_DRIFT
  }

  public enum EntityType {
    DEVICE,
    IP_MAC_BINDING,
    ISP,
    PROTOCOL,
    APP
  }

  public enum Severity {
    INFO,
    WARNING,
    CRITICAL
  }
}
