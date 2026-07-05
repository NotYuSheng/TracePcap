package com.tracepcap.intelligence.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
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

  @Column(nullable = false, unique = true)
  private String cidr;

  /** Whether matching IPs are forced to "PRIVATE" (internal) or "PUBLIC" (external). */
  @Column(nullable = false)
  private String classification;

  @Column(name = "created_at", nullable = false)
  private LocalDateTime createdAt;
}
