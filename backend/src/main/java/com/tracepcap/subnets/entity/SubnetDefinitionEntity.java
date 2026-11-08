package com.tracepcap.subnets.entity;

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

  @Column(nullable = false, length = 50)
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

  /** Null for the shared default; set for a network's own entry (#915 phase 4). */
  @Column(name = "network_id")
  private UUID networkId;

  /** A network entry that hides the default's subnet for this CIDR in that network. */
  @Builder.Default
  @Column(nullable = false)
  private boolean hidden = false;

  // The staleness baseline (#363) is per network now: SubnetNetworkBaselineEntity.

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
