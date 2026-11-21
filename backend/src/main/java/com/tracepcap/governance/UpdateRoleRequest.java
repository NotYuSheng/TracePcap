package com.tracepcap.governance;

import jakarta.validation.constraints.Size;
import java.util.Set;
import lombok.Data;

/**
 * A change to a role: what it may do, its name and description (custom roles only), and/or making
 * it the default. Omitted fields stay as they are.
 */
@Data
public class UpdateRoleRequest {
  /** Every permission the role should have, replacing its current set. */
  private Set<PermissionAction> permissions;
  /** True makes this the role for someone whose sign-in carries none (false is ignored). */
  private Boolean defaultRole;

  /** A custom role's name. Built-in roles keep theirs. */
  @Size(max = 60)
  private String label;
  /** A custom role's description; empty clears it. */
  @Size(max = 255)
  private String description;
}
