package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.dto.NetworkSettingsDto;
import com.tracepcap.monitor.dto.CreateNetworkRequest;
import com.tracepcap.monitor.dto.NetworkDto;
import com.tracepcap.monitor.dto.UpdateNetworkRequest;
import com.tracepcap.monitor.service.NetworkService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/monitor/networks")
@RequiredArgsConstructor
@Tag(name = "Monitor Networks", description = "Manage monitored networks")
public class NetworkController {

  private final NetworkService networkService;

  @GetMapping
  @Operation(summary = "List all monitored networks")
  public List<NetworkDto> getAllNetworks() {
    return networkService.getAllNetworks();
  }

  @GetMapping("/{networkId}")
  @Operation(summary = "Get a single network by ID")
  public NetworkDto getNetwork(@PathVariable UUID networkId) {
    return networkService.getNetwork(networkId);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(summary = "Create a new monitored network")
  public NetworkDto createNetwork(@Valid @RequestBody CreateNetworkRequest request) {
    return networkService.createNetwork(request);
  }

  @PatchMapping("/{networkId}")
  @Operation(summary = "Update a network's metadata")
  public NetworkDto updateNetwork(
      @PathVariable UUID networkId, @Valid @RequestBody UpdateNetworkRequest request) {
    return networkService.updateNetwork(networkId, request);
  }

  @GetMapping("/{networkId}/settings")
  @Operation(summary = "Get a network's settings (inactivity rule)")
  public NetworkSettingsDto getSettings(@PathVariable UUID networkId) {
    return networkService.getSettings(networkId);
  }

  @PutMapping("/{networkId}/settings")
  @Operation(
      summary = "Replace a network's settings (inactivity rule)",
      description =
          "inactivityMode SNAPSHOTS: a device, IP or protocol is 'no longer seen' once missing from"
              + " the last inactivityThreshold captures. DAYS: once not seen for more than"
              + " inactivityThreshold days, counted from the latest capture. Before that it's"
              + " 'quiet'. Default SNAPSHOTS / 1, which is the behaviour before this setting.")
  public NetworkSettingsDto updateSettings(
      @PathVariable UUID networkId, @Valid @RequestBody NetworkSettingsDto settings) {
    return networkService.updateSettings(networkId, settings);
  }

  @DeleteMapping("/{networkId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Delete a network")
  public void deleteNetwork(@PathVariable UUID networkId) {
    networkService.deleteNetwork(networkId);
  }
}
