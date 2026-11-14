package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.segments.NetworkSegmentsResponse;
import com.tracepcap.analysis.repository.DhcpLeaseRepository;
import com.tracepcap.analysis.service.NetworkSegments;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.repository.FileRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.ArrayList;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
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

  private final DhcpLeaseRepository leases;
  private final FileRepository files;

  @GetMapping("/{fileId}/network-segments")
  @Transactional(readOnly = true)
  @Operation(
      summary = "The networks a capture holds",
      description =
          "Leases grouped by the network that handed them out: its 802.1Q VLAN, else its DHCP"
              + " server's MAC, with the router, domain and lease time it gave. Overlaps are"
              + " networks using the same range, with the addresses leased on more than one;"
              + " each such address is a different machine per network.")
  public NetworkSegmentsResponse segments(@PathVariable UUID fileId) {
    if (!files.existsById(fileId)) throw new ResourceNotFoundException("File not found: " + fileId);
    var r = NetworkSegments.of(leases.findByFileId(fileId));
    var segments = new ArrayList<NetworkSegmentsResponse.Segment>();
    for (var s : r.segments()) {
      var clients = s.clients().stream().map(c -> new NetworkSegmentsResponse.Client(c.ip(), c.mac(), c.hostname())).toList();
      segments.add(
          new NetworkSegmentsResponse.Segment(
              s.key(), s.label(), s.vlanId(), s.serverMac(), new ArrayList<>(s.serverIds()),
              new ArrayList<>(s.routers()), new ArrayList<>(s.domains()), new ArrayList<>(s.leaseSeconds()),
              s.cidr(), clients));
    }
    var overlaps =
        r.overlaps().stream()
            .map(o -> new NetworkSegmentsResponse.Overlap(o.cidr(), o.segmentKeys(), o.sharedAddresses()))
            .toList();
    return new NetworkSegmentsResponse(segments, overlaps);
  }
}
