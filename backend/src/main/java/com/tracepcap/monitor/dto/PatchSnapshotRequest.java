package com.tracepcap.monitor.dto;

import java.util.List;
import lombok.Data;

@Data
public class PatchSnapshotRequest {
  private String context;
  private String notes;
  /** null = leave overrides unchanged; empty list = remove all (revert to global); non-empty = replace */
  private List<SubnetOverrideInput> subnetOverrides;
}
