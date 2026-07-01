package com.tracepcap.insights.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
    name = "node_roles",
    uniqueConstraints = @UniqueConstraint(columnNames = {"entity_type", "entity_key"}))
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NodeRoleEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "entity_type", nullable = false, length = 20)
  private String entityType;

  @Column(name = "entity_key", nullable = false, length = 255)
  private String entityKey;

  @Column(name = "role_label", length = 100)
  private String roleLabel;

  @Column(name = "role_description", columnDefinition = "TEXT")
  private String roleDescription;

  @Builder.Default
  @Column(name = "llm_suggested", nullable = false)
  private boolean llmSuggested = false;

  @Builder.Default
  @Column(name = "confirmed_by_human", nullable = false)
  private boolean confirmedByHuman = false;

  // ── Staleness baseline (#369) ───────────────────────────────────────────────
  // Captured when a human confirms the label; compared against current node
  // properties on each new snapshot to detect behavioural drift.

  @Column(name = "labeled_at")
  private LocalDateTime labeledAt;

  @Column(name = "baseline_file_id")
  private UUID baselineFileId;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "baseline_properties", columnDefinition = "jsonb")
  private Map<String, Object> baselineProperties;

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
