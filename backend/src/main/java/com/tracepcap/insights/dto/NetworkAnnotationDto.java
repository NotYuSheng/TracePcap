package com.tracepcap.insights.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NetworkAnnotationDto {
  private UUID id;
  private UUID networkId;
  private UUID snapshotId;
  private String body;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
