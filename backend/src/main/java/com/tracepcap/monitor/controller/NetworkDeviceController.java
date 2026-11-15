package com.tracepcap.monitor.controller;

import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.monitor.dto.DeviceLinkRequest;
import com.tracepcap.monitor.dto.DeviceLinkSuggestionDto;
import com.tracepcap.monitor.dto.NetworkDeviceCountsDto;
import com.tracepcap.monitor.dto.NetworkDeviceDto;
import com.tracepcap.monitor.service.NetworkDeviceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** A monitored network's devices across its snapshots, recognised by MAC (#918 slice 4). */
@RestController
@RequestMapping("/monitor/networks")
@RequiredArgsConstructor
@Tag(name = "Network Devices", description = "Devices across a monitored network's snapshots")
public class NetworkDeviceController {

  private final NetworkDeviceService service;

  @GetMapping("/{networkId}/devices")
  @Operation(
      summary = "A network's devices across its snapshots",
      description =
          "One row per MAC: the addresses it used, the snapshots it was seen in, its label and any"
              + " irregularities (duplicate MAC, virtual machine or container MAC, private MAC)."
              + " show = irregular or private narrows the list; q searches name, MAC, address,"
              + " vendor and label. Most recently seen first.")
  public PagedResponse<NetworkDeviceDto> list(
      @PathVariable UUID networkId,
      @RequestParam(required = false) String q,
      @RequestParam(required = false) String show,
      @RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "25") int pageSize) {
    return service.list(networkId, q, show, page, pageSize);
  }

  @GetMapping("/{networkId}/device-counts")
  @Operation(summary = "How many devices a network has: all, irregular, and with a private MAC")
  public NetworkDeviceCountsDto counts(@PathVariable UUID networkId) {
    return service.counts(networkId);
  }

  @GetMapping("/{networkId}/device-link-suggestions")
  @Operation(
      summary = "Private MACs that look like one device",
      description =
          "Pairs of private (device-chosen) MACs where one stopped before the other began and they"
              + " share a DHCP fingerprint, hostname, TLS fingerprints or signed-in user, with"
              + " nothing against it. Suggestions only; undecided pairs, strongest first.")
  public List<DeviceLinkSuggestionDto> suggestions(@PathVariable UUID networkId) {
    return service.suggestions(networkId);
  }

  @PostMapping("/{networkId}/device-links")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Record that two MACs are one device, or not",
      description = "Needs the HOST_OCCUPANCY permission. Audited. Linked MACs show as one device.")
  public NetworkDeviceDto.Link decide(@PathVariable UUID networkId, @Valid @RequestBody DeviceLinkRequest request) {
    return service.decide(networkId, request);
  }

  @DeleteMapping("/{networkId}/device-links/{linkId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Undo a same / not-the-same decision", description = "Needs the HOST_OCCUPANCY permission. Audited.")
  public void undo(@PathVariable UUID networkId, @PathVariable Long linkId) {
    service.undo(networkId, linkId);
  }
}
