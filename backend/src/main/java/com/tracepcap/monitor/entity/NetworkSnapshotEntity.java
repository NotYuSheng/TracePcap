package com.lanturn.monitor.entity;

import com.lanturn.file.entity.FileEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "network_snapshots")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkSnapshotEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "network_id", nullable = false)
  private NetworkEntity network;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id", nullable = false)
  private FileEntity file;

  @Column(name = "snapshot_order", nullable = false)
  private int snapshotOrder;

  @Builder.Default
  @Column(name = "is_baseline", nullable = false)
  private boolean isBaseline = false;

  @Column(name = "context")
  private String context;

  @Column(name = "notes")
  private String notes;

  @CreationTimestamp
  @Column(name = "added_at", nullable = false, updatable = false)
  private LocalDateTime addedAt;
}
