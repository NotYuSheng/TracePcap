package com.lanturn.monitor.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "baseline_definitions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BaselineDefinitionEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "network_id", nullable = false)
  private NetworkEntity network;

  @Enumerated(EnumType.STRING)
  @Column(name = "entry_type", nullable = false, length = 50)
  private BaselineEntryType entryType;

  @Column(name = "entity_key", nullable = false, length = 255)
  private String entityKey;

  @Column(name = "entity_value", length = 255)
  private String entityValue;

  @Column(columnDefinition = "TEXT")
  private String notes;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  public enum BaselineEntryType {
    DEVICE,
    IP_MAC_BINDING,
    GATEWAY,
    PROTOCOL,
    APP,
    VPN_FINGERPRINT
  }
}
