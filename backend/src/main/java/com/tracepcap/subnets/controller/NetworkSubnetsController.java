package com.tracepcap.subnets.controller;

import com.tracepcap.subnets.dto.SubnetDefinitionDto;
import com.tracepcap.subnets.dto.UpsertSubnetRequest;
import com.tracepcap.subnets.service.SubnetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

/** A network's own subnet entries, layered on the shared default (#915 phase 4). */
@RestController
@RequestMapping("/monitor/networks")
@RequiredArgsConstructor
@Tag(name = "Network address configuration", description = "A network's own entries on top of the shared default")
public class NetworkSubnetsController {

  private final SubnetService subnetService;

  @GetMapping("/{networkId}/subnets")
  @Operation(
      summary = "A network's subnets: its own entries and the default's",
      description =
          "Each row's scope is network (the network's own entry, possibly hiding or overriding the"
              + " default's) or default.")
  public List<SubnetDefinitionDto> list(@PathVariable UUID networkId) {
    return subnetService.listForNetwork(networkId);
  }

  @PostMapping("/{networkId}/subnets")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Set the network's subnet for a CIDR, or hide the default's",
      description = "An override or an addition; with hidden=true, hides the default's subnet. Needs NETWORK_SETTINGS. Audited.")
  public SubnetDefinitionDto put(@PathVariable UUID networkId, @RequestBody UpsertSubnetRequest req) {
    return subnetService.putForNetwork(networkId, req);
  }

  @DeleteMapping("/{networkId}/subnets/{subnetId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Remove the network's entry, so the default applies again", description = "Needs NETWORK_SETTINGS. Audited.")
  public void revert(@PathVariable UUID networkId, @PathVariable Long subnetId) {
    subnetService.deleteForNetwork(networkId, subnetId);
  }
}
