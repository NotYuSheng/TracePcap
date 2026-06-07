package com.tracepcap.monitor.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "snapshot_subnet_overrides")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SnapshotSubnetOverrideEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "snapshot_id", nullable = false)
  private NetworkSnapshotEntity snapshot;

  @Column(nullable = false, length = 50)
  private String cidr;

  @Column(length = 255)
  private String label;

  @Column(columnDefinition = "TEXT")
  private String description;

  @Builder.Default
  @Column(nullable = false)
  private boolean inherited = false;
}
