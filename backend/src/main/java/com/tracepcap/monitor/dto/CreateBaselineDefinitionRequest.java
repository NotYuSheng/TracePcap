package com.lanturn.monitor.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CreateBaselineDefinitionRequest {
  @NotBlank private String entryType;
  @NotBlank private String entityKey;
  private String entityValue;
  private String notes;
}
