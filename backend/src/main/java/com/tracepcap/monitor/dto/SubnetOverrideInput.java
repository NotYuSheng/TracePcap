package com.tracepcap.monitor.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SubnetOverrideInput {
  /** Checked and written by Cidr.normaliseIpv4 in SnapshotService: one CIDR rule (#1351). */
  @NotBlank
  private String cidr;
  private String label;
  private String description;
  private boolean inherited;
}
