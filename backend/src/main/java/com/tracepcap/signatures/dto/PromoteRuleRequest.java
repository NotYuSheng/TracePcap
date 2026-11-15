package com.tracepcap.signatures.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Promote a capture rule to a global rule (#925 phase 3). */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PromoteRuleRequest {
  /** Keep the capture rule as well (true), or remove it once the global copy exists (false). */
  private boolean keepOriginal = true;
}
