package com.tracepcap.subnets.entity;

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
@Table(name = "subnet_definitions")
@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SubnetDefinitionEntity {

  @EqualsAndHashCode.Include
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true, length = 50)
  private String cidr;

  @Column(length = 100)
  private String label;

  @Column(columnDefinition = "TEXT")
  private String description;

  @Builder.Default
  @Column(nullable = false, length = 10)
  private String source = "MANUAL";

  @Builder.Default
  @Column(nullable = false)
  private boolean confirmed = false;

  // ── Staleness baseline (#363) ─────────────────────────────────────────────
  // Captured when an analyst confirms the label: the subnet's composition (dominant member device
  // types + protocols) at that moment. Each new snapshot is compared against this; drift sets
  // staleSince/staleFields until the analyst re-labels or dismisses.

  @Column(name = "labeled_at")
  private LocalDateTime labeledAt;

  @Column(name = "baseline_file_id")
  private UUID baselineFileId;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "baseline_composition", columnDefinition = "jsonb")
  private Map<String, Object> baselineComposition;

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
