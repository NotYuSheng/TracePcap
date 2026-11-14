package com.tracepcap.monitor.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/** Two MACs are one device (same) or not (not_same), with the analyst's reason (#918 slice 4b). */
@Data
public class DeviceLinkRequest {
  @NotBlank
  @Pattern(regexp = "(?i)([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", message = "must be a MAC address")
  private String macA;

  @NotBlank
  @Pattern(regexp = "(?i)([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", message = "must be a MAC address")
  private String macB;

  @NotBlank
  @Pattern(regexp = "same|not_same", message = "must be same or not_same")
  private String decision;

  @NotBlank
  @Size(max = 2000)
  private String reason;
}
