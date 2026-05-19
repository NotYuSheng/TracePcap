package com.tracepcap.monitor.dto;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ChangeEventDto {
  private UUID id;
  private UUID networkId;
  private UUID fromSnapshotId;
  private UUID toSnapshotId;
  private String changeType;
  private String entityType;
  private String entityKey;
  private Map<String, Object> oldValue;
  private Map<String, Object> newValue;
  private String severity;
  private LocalDateTime detectedAt;
  private boolean reviewed;
  private String notes;
}
