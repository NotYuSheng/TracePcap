package com.tracepcap.insights.dto;

import java.time.LocalDateTime;
import lombok.Data;

@Data
public class CreateExternalEventRequest {
  private LocalDateTime eventTime;
  private String title;
  private String description;
}
