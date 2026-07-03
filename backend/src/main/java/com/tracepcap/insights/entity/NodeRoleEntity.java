package com.tracepcap.insights.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
    name = "node_roles",
    uniqueConstraints = @UniqueConstraint(columnNames = {"file_id", "entity_type", "entity_key"}))
@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NodeRoleEntity {

  @EqualsAndHashCode.Include
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  /** The file (a monitor snapshot is a file) this role classification belongs to (#369). */
  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "entity_type", nullable = false, length = 20)
  private String entityType;

  @Column(name = "entity_key", nullable = false, length = 255)
  private String entityKey;

  @Column(name = "role_label", length = 100)
  private String roleLabel;

  @Column(name = "role_description", columnDefinition = "TEXT")
  private String roleDescription;

  /** How this classification arrived: MANUAL | AI | CARRIED_FORWARD (#369). */
  @Builder.Default
  @Column(name = "origin", nullable = false, length = 20)
  private String origin = "MANUAL";

  @Builder.Default
  @Column(name = "llm_suggested", nullable = false)
  private boolean llmSuggested = false;

  @Builder.Default
  @Column(name = "confirmed_by_human", nullable = false)
  private boolean confirmedByHuman = false;

  // ── Per-file properties + staleness (#369) ──────────────────────────────────
  // observedProperties is the snapshot of this node's key properties in THIS file
  // (device type, MAC, dominant protocols, external orgs). It doubles as the drift
  // baseline carried into the next snapshot. staleSince/staleFields are set when a
  // carried-forward label drifts from that baseline at ingest.

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "observed_properties", columnDefinition = "jsonb")
  private Map<String, Object> observedProperties;

  @Column(name = "stale_since")
  private LocalDateTime staleSince;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "stale_fields", columnDefinition = "jsonb")
  private List<String> staleFields;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
