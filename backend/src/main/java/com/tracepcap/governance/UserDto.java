package com.tracepcap.governance;

import java.time.LocalDateTime;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Someone who has signed in: the roles their last sign-in carried, and what those add up to. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
  private String username;
  private String displayName;
  /** TracePcap roles their sign-in carried, in the order Settings lists them. */
  private List<String> roles;
  /** True when it carried none, so they get the default role. */
  private boolean defaultRole;
  /**
   * Client roles their sign-in carried that TracePcap has no role for: a typo in Keycloak, or a
   * role deleted here. They give nothing.
   */
  private List<String> unknownRoles;
  /** How many permissions their roles add up to. */
  private int permissionCount;
  private LocalDateTime firstSeen;
  private LocalDateTime lastSeen;
}
