package com.tracepcap.governance;

import java.util.Set;
import lombok.Data;

/** A change to a role: what it may do, and/or making it the default. Omitted fields stay as they are. */
@Data
public class UpdateRoleRequest {
  /** Every permission the role should have, replacing its current set. */
  private Set<PermissionAction> permissions;
  /** True makes this the role for someone whose sign-in carries none (false is ignored). */
  private Boolean defaultRole;
}
