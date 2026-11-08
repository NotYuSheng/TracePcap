package com.tracepcap.monitor.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "networks")
@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkEntity {

  @EqualsAndHashCode.Include
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(nullable = false, length = 255)
  private String name;

  @Column(columnDefinition = "TEXT")
  private String description;

  /** SNAPSHOTS | DAYS: see NetworkSettingsDto (#488). Default SNAPSHOTS, 1 = today's behaviour. */
  @Builder.Default
  @Column(name = "inactivity_mode", nullable = false, length = 10)
  private String inactivityMode = "SNAPSHOTS";

  @Builder.Default
  @Column(name = "inactivity_threshold", nullable = false)
  private int inactivityThreshold = 1;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
