package com.tracepcap.monitor.dto;

import jakarta.validation.Valid;
import java.util.List;
import lombok.Data;

@Data
public class PatchSnapshotRequest {
  private String context;
  private String notes;
  /** null = leave overrides unchanged; empty list = remove all (revert to global); non-empty = replace */
  private List<@Valid SubnetOverrideInput> subnetOverrides;
}
