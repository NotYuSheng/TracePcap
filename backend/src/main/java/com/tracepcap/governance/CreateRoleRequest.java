package com.tracepcap.governance;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/** A new custom role. Someone gets it from the Keycloak client role named {@link #key}. */
@Data
public class CreateRoleRequest {
  /** The Keycloak client role on the app's client that gives this role. Can't change later. */
  @NotBlank
  @Size(max = 100)
  @Pattern(
      regexp = PermissionService.ROLE_KEY_PATTERN,
      message = "letters, digits, '-', '_' and '.' only, starting with a letter or digit")
  private String key;

  @NotBlank
  @Size(max = 60)
  private String label;

  @Size(max = 255)
  private String description;

  /** A role whose permissions the new one starts with. Omitted: it starts with seeing captures only. */
  private String copyFrom;
}
