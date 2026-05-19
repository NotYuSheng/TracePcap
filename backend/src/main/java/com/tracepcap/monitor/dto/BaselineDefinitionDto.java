package com.tracepcap.monitor.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BaselineDefinitionDto {
  private UUID id;
  private UUID networkId;
  private String entryType;
  private String entityKey;
  private String entityValue;
  private String notes;
  private LocalDateTime createdAt;
}
