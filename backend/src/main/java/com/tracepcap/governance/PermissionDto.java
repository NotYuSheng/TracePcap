package com.tracepcap.governance;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** One permission in the catalogue, and whether the caller has it. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionDto {
  private PermissionAction action;
  private String label;
  private String description;
  private PermissionAction.Group group;
  /** The group's heading, e.g. "Detection rules". */
  private String groupLabel;
  /** The catalogue's suggested lowest built-in role: viewer, analyst, lead or admin. */
  private String suggestedRole;
  /** True for the two no role's set can change: everyone sees captures, only admin manages roles. */
  private boolean fixed;
  /** Whether the current caller may do this. */
  private boolean allowed;
  /** Why not, in words the UI shows next to the greyed-out control. Null when allowed. */
  private String reason;
}
