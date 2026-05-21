package com.tracepcap.subnets.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "subnet_definitions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SubnetDefinitionEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true, length = 50)
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

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
