package com.lanturn.monitor.dto;

import lombok.Data;

@Data
public class PatchSnapshotRequest {
  private String context;
  private String notes;
}
