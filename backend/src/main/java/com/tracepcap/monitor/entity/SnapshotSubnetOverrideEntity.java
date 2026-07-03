package com.tracepcap.monitor.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "snapshot_subnet_overrides")
@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SnapshotSubnetOverrideEntity {

  @EqualsAndHashCode.Include
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ToString.Exclude
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
