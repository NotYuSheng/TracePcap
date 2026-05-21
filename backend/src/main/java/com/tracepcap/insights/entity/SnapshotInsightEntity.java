package com.lanturn.insights.entity;

import com.lanturn.monitor.entity.NetworkSnapshotEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "snapshot_insights")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SnapshotInsightEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "snapshot_id", nullable = false)
  private NetworkSnapshotEntity snapshot;

  @CreationTimestamp
  @Column(name = "generated_at", nullable = false, updatable = false)
  private LocalDateTime generatedAt;

  @Column(name = "model_used", length = 100)
  private String modelUsed;

  @Builder.Default
  @Column(nullable = false, length = 20)
  private String status = "COMPLETED";

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(columnDefinition = "jsonb")
  private String content;

  @Column(name = "error_message", columnDefinition = "TEXT")
  private String errorMessage;

  @Column(name = "audience", length = 20)
  private String audience;

  @Column(name = "focus", length = 20)
  private String focus;
}
