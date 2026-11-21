package com.tracepcap.governance;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Who the caller is and what they may change (#915). */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MeDto {
  /** The login's username, or {@code system} when login is off. */
  private String username;
  private boolean authEnabled;
  /** Keycloak client role admin with login on; SYSTEM_SETTINGS_EDITABLE with login off. */
  private boolean admin;
  /** Whether the caller may change roles (the admin role only). */
  private boolean canManagePermissions;
  /** The TracePcap roles that apply to the caller: from their sign-in, or the default role. */
  private List<String> roles;
  private List<PermissionDto> permissions;
}
