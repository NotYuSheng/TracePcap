package com.tracepcap.insights.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import lombok.Data;

@Data
public class CreateExternalEventRequest {
  @NotNull private LocalDateTime eventTime;
  @NotBlank private String title;
  private String description;
}
