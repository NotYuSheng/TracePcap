package com.tracepcap.intelligence.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IpOrgRuleDto {
  private Long id;
  private String label;
  private String cidr;
}
