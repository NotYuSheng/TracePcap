package com.tracepcap.analysis.dto.segments;

import java.util.List;

/**
 * The networks a capture holds, told apart by their DHCP leases (#462 phase 1), and the ones that
 * use the same range.
 */
public record NetworkSegmentsResponse(List<Segment> segments, List<Overlap> overlaps) {

  /**
   * One network: what identifies it and the clients it leased addresses to.
   *
   * @param key how it was told apart: vlan:N, server:MAC or id:IP|domain
   * @param label its domain, VLAN or DHCP server, for display
   */
  public record Segment(
      String key,
      String label,
      Integer vlanId,
      String serverMac,
      List<String> serverIds,
      List<String> routers,
      List<String> domains,
      List<Long> leaseSeconds,
      String cidr,
      List<Client> clients) {}

  public record Client(String ip, String mac, String hostname) {}

  /** Networks whose ranges overlap, and the addresses leased on more than one of them. */
  public record Overlap(String cidr, List<String> segmentKeys, List<String> sharedAddresses) {}
}
