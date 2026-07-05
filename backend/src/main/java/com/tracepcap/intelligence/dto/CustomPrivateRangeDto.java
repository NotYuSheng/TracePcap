package com.tracepcap.intelligence.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomPrivateRangeDto {
  private Long id;
  private String cidr;
  /** "PRIVATE" (treat as internal) or "PUBLIC" (treat as external). Defaults to PRIVATE. */
  private String classification;
}
