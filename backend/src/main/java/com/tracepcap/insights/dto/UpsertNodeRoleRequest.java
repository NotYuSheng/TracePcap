package com.tracepcap.insights.dto;

import java.util.UUID;
import lombok.Data;

@Data
public class UpsertNodeRoleRequest {
  private String entityType;
  private String entityKey;
  private String roleLabel;
  private String roleDescription;
  private boolean confirmedByHuman;

  /**
   * Optional file context. When present and the label is confirmed by a human, a property baseline
   * is captured from this file so future snapshots can detect drift (#369).
   */
  private UUID fileId;
}
