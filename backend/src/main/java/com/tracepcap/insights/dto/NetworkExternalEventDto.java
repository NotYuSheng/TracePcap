package com.tracepcap.insights.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NetworkExternalEventDto {
  private UUID id;
  private UUID networkId;
  private LocalDateTime eventTime;
  private String title;
  private String description;
  private LocalDateTime createdAt;
}
