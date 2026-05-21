package com.tracepcap.monitor.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NetworkSnapshotDto {
  private UUID id;
  private UUID networkId;
  private UUID fileId;
  private String fileName;
  private int snapshotOrder;
  private LocalDateTime startTime;
  private LocalDateTime endTime;
  private Integer packetCount;
  private Long totalBytes;
  private long changeCount;
  private long criticalCount;
  private String context;
  private String notes;
  private boolean hasInsights;
  private LocalDateTime addedAt;
}
