package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * The networks a capture holds, told apart by their DHCP leases (#462), for modules outside
 * analysis: subnet labels are per network when two networks share a range.
 */
public interface NetworkSegmentLookup {

  /**
   * One network in a capture.
   *
   * @param key how it was told apart (vlan:N, server:MAC, id:IP|domain); stable across a monitored
   *     network's snapshots while its VLAN or DHCP server is the same
   * @param label its domain, VLAN or DHCP server, for display
   * @param cidr its range
   * @param addresses the addresses it leased, and its router's
   * @param macs its DHCP clients' and server's MACs
   * @param sharesRange whether another network in the capture uses an overlapping range
   */
  record Segment(String key, String label, String cidr, Set<String> addresses, Set<String> macs, boolean sharesRange) {}

  List<Segment> segments(UUID fileId);
}
