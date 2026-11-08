package com.tracepcap.governance;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** An override of one action's default level (#915). See V48. */
@Entity
@Table(name = "permissions")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionEntity {

  @Id
  @Column(name = "action", length = 100)
  private String action;

  @Enumerated(EnumType.STRING)
  @Column(name = "level", nullable = false, length = 20)
  private PermissionLevel level;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Column(name = "updated_by", nullable = false)
  private String updatedBy;
}
