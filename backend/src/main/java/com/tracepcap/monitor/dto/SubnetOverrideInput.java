package com.tracepcap.monitor.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class SubnetOverrideInput {
  @NotBlank
  @Pattern(
      regexp = "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)/(\\d|[12]\\d|3[0-2])$",
      message = "must be a valid CIDR block (e.g. 10.0.0.0/24)")
  private String cidr;
  private String label;
  private String description;
  private boolean inherited;
}
