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
@Table(name = "ip_org_rules")
@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IpOrgRuleEntity {

  @EqualsAndHashCode.Include
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private String label;

  @Column(nullable = false)
  private String cidr;

  @Column(name = "prefix_length", nullable = false)
  private int prefixLength;

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
