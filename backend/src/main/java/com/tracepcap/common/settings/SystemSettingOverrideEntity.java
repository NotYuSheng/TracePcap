package com.tracepcap.common.settings;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** An in-app override of a deploy-time setting (#915 phase 5). See V49. */
@Entity
@Table(name = "system_settings")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SystemSettingOverrideEntity {

  @Id
  @Column(name = "key", length = 100)
  private String key;

  @Column(name = "value", nullable = false)
  private String value;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Column(name = "updated_by", nullable = false)
  private String updatedBy;
}
