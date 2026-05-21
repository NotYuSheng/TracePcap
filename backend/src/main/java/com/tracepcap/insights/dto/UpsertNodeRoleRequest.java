package com.lanturn.insights.dto;

import lombok.Data;

@Data
public class UpsertNodeRoleRequest {
  private String entityType;
  private String entityKey;
  private String roleLabel;
  private String roleDescription;
  private boolean confirmedByHuman;
}
