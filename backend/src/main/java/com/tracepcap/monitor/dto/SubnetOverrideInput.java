package com.tracepcap.monitor.dto;

import lombok.Data;

@Data
public class SubnetOverrideInput {
  private String cidr;
  private String label;
  private String description;
  private boolean inherited;
}
