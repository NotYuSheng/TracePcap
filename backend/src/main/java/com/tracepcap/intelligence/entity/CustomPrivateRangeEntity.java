package com.tracepcap.intelligence.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "custom_private_ranges")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomPrivateRangeEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true)
  private String cidr;

  @Column
  private String label;

  @Column(name = "created_at", nullable = false)
  private LocalDateTime createdAt;
}
