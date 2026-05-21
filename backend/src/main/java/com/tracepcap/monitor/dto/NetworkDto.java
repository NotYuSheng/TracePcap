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
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
