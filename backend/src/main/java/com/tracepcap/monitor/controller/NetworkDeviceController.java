package com.tracepcap.monitor.controller;

import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.monitor.dto.NetworkDeviceCountsDto;
import com.tracepcap.monitor.dto.NetworkDeviceDto;
import com.tracepcap.monitor.service.NetworkDeviceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
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
}
