package com.tracepcap.monitor.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NetworkDto {
  private UUID id;
  private String name;
  private String description;
  private int snapshotCount;
  private long criticalChanges;
  private long warningChanges;
  private boolean hasInsights;
  /** Per-network settings (#488): the inactivity rule the drift panels apply. */
  private NetworkSettingsDto settings;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
