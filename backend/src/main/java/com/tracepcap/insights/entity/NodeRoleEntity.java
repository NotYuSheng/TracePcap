package com.tracepcap.insights.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

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

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
