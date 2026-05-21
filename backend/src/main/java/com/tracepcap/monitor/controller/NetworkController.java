package com.lanturn.monitor.controller;

import com.lanturn.monitor.dto.CreateNetworkRequest;
import com.lanturn.monitor.dto.NetworkDto;
import com.lanturn.monitor.service.NetworkService;
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

  @DeleteMapping("/{networkId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteNetwork(@PathVariable UUID networkId) {
    networkService.deleteNetwork(networkId);
  }
}
