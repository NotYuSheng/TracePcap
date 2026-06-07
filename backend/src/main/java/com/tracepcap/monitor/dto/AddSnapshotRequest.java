package com.tracepcap.monitor.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.UUID;
import lombok.Data;

@Data
public class AddSnapshotRequest {
  @NotNull private UUID fileId;
  private List<@Valid SubnetOverrideInput> subnetOverrides;
}
