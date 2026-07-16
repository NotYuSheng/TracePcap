package com.tracepcap.analysis.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One hostname claim for one IP in one capture — a REPORTED-grade observation (#512 slice 4).
 * All claims are kept; winner-picking happens at adjudication, never at write time. See
 * {@code docs/architecture/layers.rst} ("Extract records observations, not conclusions").
 */
@Entity
@Table(name = "hostname_claims")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HostnameClaimEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  @Column(nullable = false, length = 255)
  private String hostname;

  /** Which protocol asserted it: dhcp | mdns | nbns | reverse_dns. */
  @Column(nullable = false, length = 20)
  private String source;

  @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
  private LocalDateTime createdAt;
}
