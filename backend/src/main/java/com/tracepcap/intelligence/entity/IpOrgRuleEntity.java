package com.tracepcap.intelligence.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "ip_org_rules")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IpOrgRuleEntity {

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
}
