package com.tracepcap.insights.entity;

import com.tracepcap.monitor.entity.NetworkEntity;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "network_annotations")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkAnnotationEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "network_id", nullable = false)
  private NetworkEntity network;

  /** Optional association with a specific snapshot. */
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "snapshot_id")
  private NetworkSnapshotEntity snapshot;

  @Column(nullable = false, columnDefinition = "TEXT")
  private String body;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
