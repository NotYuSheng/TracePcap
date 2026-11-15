package com.tracepcap.signatures.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** A global rule switched off within one network's views (#925 phase 4). */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RuleSuppressionDto {
  private UUID ruleId;
  private String ruleName;
  private LocalDateTime createdAt;
  private String createdBy;
}
