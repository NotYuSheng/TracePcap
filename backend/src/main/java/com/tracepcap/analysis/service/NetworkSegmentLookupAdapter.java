package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.DhcpLeaseRepository;
import com.tracepcap.analysis.spi.NetworkSegmentLookup;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Serves {@link NetworkSegmentLookup} from the capture's DHCP leases. */
@Component
@RequiredArgsConstructor
public class NetworkSegmentLookupAdapter implements NetworkSegmentLookup {

  private final DhcpLeaseRepository leases;

  @Override
  @Transactional(readOnly = true)
  public List<Segment> segments(UUID fileId) {
    var r = NetworkSegments.of(leases.findByFileId(fileId));
    Set<String> sharing = new HashSet<>();
    r.overlaps().forEach(o -> sharing.addAll(o.segmentKeys()));
    var macs = r.macsBySegment();
    List<Segment> out = new ArrayList<>();
    for (var s : r.segments()) {
      Set<String> addrs = new LinkedHashSet<>(s.routers());
      s.clients().forEach(c -> addrs.add(c.ip()));
      out.add(new Segment(s.key(), s.label(), s.cidr(), addrs, macs.getOrDefault(s.key(), Set.of()), sharing.contains(s.key())));
    }
    return out;
  }
}
