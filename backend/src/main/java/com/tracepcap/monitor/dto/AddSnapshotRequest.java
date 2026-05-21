package com.lanturn.monitor.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;
import lombok.Data;

@Data
public class AddSnapshotRequest {
  @NotNull private UUID fileId;
}
