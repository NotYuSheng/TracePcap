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
  /** Whether the caller may change the permission levels (always admin-only). */
  private boolean canManagePermissions;
  private List<PermissionDto> permissions;
}
