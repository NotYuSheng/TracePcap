package com.tracepcap.policy.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IpOrgRuleDto {
  private Long id;
  private String label;
  private String cidr;

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
