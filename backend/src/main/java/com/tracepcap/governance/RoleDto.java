package com.tracepcap.governance;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** A role and what it may do. Who has it is decided in Keycloak, by its key. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleDto {
  /** The Keycloak client role (on the app's client) that gives this role. */
  private String key;
  private String label;
  private String description;
  private boolean builtIn;
  /** The role someone gets when their sign-in carries none of TracePcap's roles. */
  private boolean defaultRole;
  /** False for the admin role, which always has every permission. */
  private boolean editable;
  private List<PermissionAction> permissions;
}
