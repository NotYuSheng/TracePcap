package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.segments.NetworkSegmentsResponse;
import com.tracepcap.analysis.repository.DhcpLeaseRepository;
import com.tracepcap.analysis.repository.DhcpUnansweredClientRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.repository.FileRepository;
import java.util.ArrayList;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** The networks a capture holds, from its DHCP leases (#462), for the API and the report. */
@Service
@RequiredArgsConstructor
public class NetworkSegmentService {

  private final DhcpLeaseRepository leases;
  private final DhcpUnansweredClientRepository unansweredClients;
  private final FileRepository files;

  @Transactional(readOnly = true)
  public NetworkSegmentsResponse segments(UUID fileId) {
    if (!files.existsById(fileId)) throw new ResourceNotFoundException("File not found: " + fileId);
    var r = NetworkSegments.of(leases.findByFileId(fileId));
    // Clients nobody answered go with the network on the VLAN they asked on, when there is one.
    var unplaced = new ArrayList<NetworkSegmentsResponse.UnansweredClient>();
    var byVlan = new java.util.HashMap<Integer, java.util.List<NetworkSegmentsResponse.UnansweredClient>>();
    var vlans = new java.util.HashSet<Integer>();
    r.segments().forEach(s -> { if (s.vlanId() != null) vlans.add(s.vlanId()); });
    for (var u : unansweredClients.findByFileId(fileId)) {
      var c = new NetworkSegmentsResponse.UnansweredClient(u.getMac(), u.getHostname(), u.getVlanId(), u.getRequests());
      if (u.getVlanId() != null && vlans.contains(u.getVlanId())) {
        byVlan.computeIfAbsent(u.getVlanId(), k -> new ArrayList<>()).add(c);
      } else {
        unplaced.add(c);
      }
    }
    var segments = new ArrayList<NetworkSegmentsResponse.Segment>();
    for (var s : r.segments()) {
      var clients = s.clients().stream().map(c -> new NetworkSegmentsResponse.Client(c.ip(), c.mac(), c.hostname())).toList();
      segments.add(
          new NetworkSegmentsResponse.Segment(
              s.key(), s.label(), s.vlanId(), s.serverMac(), new ArrayList<>(s.serverIds()),
              new ArrayList<>(s.routers()), new ArrayList<>(s.domains()), new ArrayList<>(s.leaseSeconds()),
              s.cidr(), clients,
              s.vlanId() == null ? java.util.List.of() : byVlan.getOrDefault(s.vlanId(), java.util.List.of())));
    }
    var overlaps =
        r.overlaps().stream()
            .map(o -> new NetworkSegmentsResponse.Overlap(o.cidr(), o.segmentKeys(), o.sharedAddresses()))
            .toList();
    return new NetworkSegmentsResponse(segments, overlaps, unplaced);
  }
}
