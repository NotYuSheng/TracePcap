package com.tracepcap.signatures.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Whether captures are up to date with the enabled detection rules (#925 phase 2). */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RuleSyncStatusDto {
  /** Completed captures considered. */
  private int captures;
  /** Captures not yet checked against the current version of at least one enabled rule. */
  private int staleCaptures;
  /** Captures where a payload rule couldn't be re-checked because their packets were deleted. */
  private int uncheckableCaptures;
  /** For one capture: the enabled rules it's out of date for. */
  @Builder.Default private List<String> staleRules = List.of();
  /** For one capture: the rules that couldn't be re-checked (packets deleted by retention). */
  @Builder.Default private List<String> uncheckableRules = List.of();
}
