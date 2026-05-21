package com.tracepcap.insights.dto;

import java.util.UUID;
import lombok.Data;

@Data
public class CreateAnnotationRequest {
  private String body;
  /** Optional — associate with a specific snapshot. */
  private UUID snapshotId;
}
