package com.tracepcap.monitor.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * An analyst's decision that two MACs in a network are one device, or not (#918 slice 4b). Kept
 * apart from the suggestions, which are worked out at read time. {@code macA < macB}.
 */
@Entity
@Table(name = "device_links")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceLinkEntity {

  public static final String SAME = "same";
  public static final String NOT_SAME = "not_same";

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "network_id", nullable = false)
  private UUID networkId;

  @Column(name = "mac_a", nullable = false, length = 50)
  private String macA;

  @Column(name = "mac_b", nullable = false, length = 50)
  private String macB;

  @Column(nullable = false, length = 10)
  private String decision;

  @Column(nullable = false, columnDefinition = "TEXT")
  private String reason;

  private String actor;

  @Column(name = "created_at", nullable = false)
  private LocalDateTime createdAt;

  @PrePersist
  void onCreate() {
    if (createdAt == null) createdAt = LocalDateTime.now();
  }
}
