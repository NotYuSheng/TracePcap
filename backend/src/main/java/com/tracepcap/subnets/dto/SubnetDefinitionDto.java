package com.lanturn.subnets.dto;

import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SubnetDefinitionDto {
  private Long id;
  private String cidr;
  private String label;
  private String description;
  private String source;
  private boolean confirmed;
  private Integer hostCount;       // populated only for detect results
  private Double densityScore;     // observed hosts / subnet capacity (0–1)
  private Integer snapshotsSeen;   // cross-snapshot consensus fields
  private Integer totalSnapshots;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;
}
