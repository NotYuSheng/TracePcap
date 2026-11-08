package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.service.NetworkService;
import com.tracepcap.policy.dto.CustomPrivateRangeDto;
import com.tracepcap.policy.dto.IpOrgRuleDto;
import com.tracepcap.policy.service.CustomPrivateRangeService;
import com.tracepcap.policy.service.IpOrgRuleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

/**
 * A network's own private/public range overrides and IP-org rules, layered on the shared default
 * per CIDR (#915 phase 4): override or add an entry, hide the default's, or revert to the default.
 */
@RestController
@RequestMapping("/monitor/networks")
@RequiredArgsConstructor
@Tag(name = "Network address configuration", description = "A network's own entries on top of the shared default")
public class NetworkAddressConfigController {

  private final NetworkService networkService;
  private final CustomPrivateRangeService privateRanges;
  private final IpOrgRuleService orgRules;

  @GetMapping("/{networkId}/custom-private-ranges")
  @Operation(summary = "A network's private/public range overrides: its own entries and the default's")
  public List<CustomPrivateRangeDto> listRanges(@PathVariable UUID networkId) {
    networkService.getNetwork(networkId);
    return privateRanges.listForNetwork(networkId);
  }

  @PostMapping("/{networkId}/custom-private-ranges")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Set the network's range override for a CIDR, or hide the default's",
      description = "With hidden=true, hides the default's entry for the CIDR. Needs NETWORK_SETTINGS. Audited.")
  public CustomPrivateRangeDto putRange(@PathVariable UUID networkId, @RequestBody CustomPrivateRangeDto dto) {
    networkService.getNetwork(networkId);
    return privateRanges.putForNetwork(networkId, dto, dto.isHidden());
  }

  @DeleteMapping("/{networkId}/custom-private-ranges/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Remove the network's range entry, so the default applies again", description = "Needs NETWORK_SETTINGS. Audited.")
  public void revertRange(@PathVariable UUID networkId, @PathVariable Long id) {
    privateRanges.deleteForNetwork(networkId, id);
  }

  @GetMapping("/{networkId}/ip-org-rules")
  @Operation(summary = "A network's IP-org rules: its own entries and the default's")
  public List<IpOrgRuleDto> listOrgRules(@PathVariable UUID networkId) {
    networkService.getNetwork(networkId);
    return orgRules.listForNetwork(networkId);
  }

  @PostMapping("/{networkId}/ip-org-rules")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Set the network's IP-org rule for a CIDR, or hide the default's",
      description = "With hidden=true, hides the default's rule for the CIDR. Needs NETWORK_SETTINGS. Audited.")
  public IpOrgRuleDto putOrgRule(@PathVariable UUID networkId, @RequestBody IpOrgRuleDto dto) {
    networkService.getNetwork(networkId);
    return orgRules.putForNetwork(networkId, dto, dto.isHidden());
  }

  @DeleteMapping("/{networkId}/ip-org-rules/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Remove the network's IP-org rule, so the default applies again", description = "Needs NETWORK_SETTINGS. Audited.")
  public void revertOrgRule(@PathVariable UUID networkId, @PathVariable Long id) {
    orgRules.deleteForNetwork(networkId, id);
  }
}
