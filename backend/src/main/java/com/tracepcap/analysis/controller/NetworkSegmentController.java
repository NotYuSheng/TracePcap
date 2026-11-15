package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.segments.NetworkSegmentsResponse;
import com.tracepcap.analysis.service.NetworkSegmentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** The networks a capture holds, from its DHCP leases (#462). */
@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(name = "Network Segments", description = "Networks in a capture, told apart by their DHCP leases")
public class NetworkSegmentController {

  private final NetworkSegmentService service;

  @GetMapping("/{fileId}/network-segments")
  @Operation(
      summary = "The networks a capture holds",
      description =
          "Leases grouped by the network that handed them out: its 802.1Q VLAN, else its DHCP"
              + " server's MAC, with the router, domain and lease time it gave. Overlaps are"
              + " networks using the same range, with the addresses leased on more than one;"
              + " each such address is a different machine per network. Clients that asked for an"
              + " address and got none are listed under the network on their VLAN, else at the top.")
  public NetworkSegmentsResponse segments(@PathVariable UUID fileId) {
    return service.segments(fileId);
  }
}
