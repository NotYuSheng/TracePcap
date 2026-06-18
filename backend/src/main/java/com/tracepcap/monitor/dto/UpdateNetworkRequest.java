package com.tracepcap.monitor.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UpdateNetworkRequest {
  @NotBlank private String name;
  private String description;
}
