package com.tracepcap.governance;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** One configurable action, the level it requires now, and whether the caller may do it. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionDto {
  private PermissionAction action;
  private String label;
  private String description;
  private PermissionLevel level;
  private PermissionLevel defaultLevel;
  /** Whether the current caller may perform this action. */
  private boolean allowed;
  /** Why not, in words the UI shows next to the greyed-out control. Null when allowed. */
  private String reason;
}
