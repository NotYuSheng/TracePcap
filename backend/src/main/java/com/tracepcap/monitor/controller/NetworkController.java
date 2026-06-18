package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.dto.CreateNetworkRequest;
import com.tracepcap.monitor.dto.NetworkDto;
import com.tracepcap.monitor.dto.UpdateNetworkRequest;
import com.tracepcap.monitor.service.NetworkService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/monitor/networks")
@RequiredArgsConstructor
public class NetworkController {

  private final NetworkService networkService;

  @GetMapping
  public List<NetworkDto> getAllNetworks() {
    return networkService.getAllNetworks();
  }

  @GetMapping("/{networkId}")
  public NetworkDto getNetwork(@PathVariable UUID networkId) {
    return networkService.getNetwork(networkId);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public NetworkDto createNetwork(@Valid @RequestBody CreateNetworkRequest request) {
    return networkService.createNetwork(request);
  }

  @PatchMapping("/{networkId}")
  public NetworkDto updateNetwork(
      @PathVariable UUID networkId, @Valid @RequestBody UpdateNetworkRequest request) {
    return networkService.updateNetwork(networkId, request);
  }

  @DeleteMapping("/{networkId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteNetwork(@PathVariable UUID networkId) {
    networkService.deleteNetwork(networkId);
  }
}
