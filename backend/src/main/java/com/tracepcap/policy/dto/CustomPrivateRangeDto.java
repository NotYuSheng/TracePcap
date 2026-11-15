package com.tracepcap.policy.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomPrivateRangeDto {
  private Long id;
  private String cidr;

  /** "PRIVATE" (treat as internal) or "PUBLIC" (treat as external). Defaults to PRIVATE. */
  @Schema(allowableValues = {"PRIVATE", "PUBLIC"}, defaultValue = "PRIVATE")
  private String classification;

  /**
   * Where the entry comes from in a network's effective list (#915 phase 4): "default", or
   * "network" for the network's own entry. Null on the default list itself.
   */
  private String scope;

  /** The network's entry hides the default's for this CIDR. */
  private boolean hidden;

  /** A network entry for a CIDR the default also has. */
  private boolean overridesDefault;
}
