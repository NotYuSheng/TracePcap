package com.lanturn.subnets.dto;

import lombok.Data;

@Data
public class UpsertSubnetRequest {
  private String cidr;
  private String label;
  private String description;
  private boolean confirmed;
}
