package com.tracepcap.monitor.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SnapshotSubnetOverrideDto {
  private Long id;
  private String cidr;
  private String label;
  private String description;
  private boolean inherited;
}
