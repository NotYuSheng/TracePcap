package com.tracepcap.policy.entity;

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

@Entity
@Table(name = "custom_private_ranges")
@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomPrivateRangeEntity {

  @EqualsAndHashCode.Include
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private String cidr;

  /** Whether matching IPs are forced to PRIVATE (internal) or PUBLIC (external). */
  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private IpClassification classification;

  @Column(name = "created_at", nullable = false)
  private LocalDateTime createdAt;

  /** Null for the shared default; set for a network's own entry (#915 phase 4). */
  @Column(name = "network_id")
  private UUID networkId;

  /** A network entry that hides the default's entry for this CIDR in that network. */
  @Column(nullable = false)
  @Builder.Default
  private boolean hidden = false;
}
