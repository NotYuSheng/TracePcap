package com.tracepcap.analysis.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** One thing a server said about itself, with how often it said it. See V85. */
@Entity
@Table(name = "service_banners")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServiceBannerEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "server_ip", nullable = false, length = 45)
  private String serverIp;

  @Column(name = "port", nullable = false)
  private int port;

  @Column(name = "kind", nullable = false, length = 32)
  private String kind;

  @Column(name = "value", nullable = false, length = 255)
  private String value;

  @Column(name = "seen_count", nullable = false)
  private int seenCount;
}
