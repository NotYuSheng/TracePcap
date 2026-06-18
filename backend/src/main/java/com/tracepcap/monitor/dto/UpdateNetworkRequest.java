package com.tracepcap.monitor.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateNetworkRequest {
  @NotBlank @Size(max = 255) private String name;
  private String description;
}
