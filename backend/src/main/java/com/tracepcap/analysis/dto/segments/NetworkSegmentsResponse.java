package com.tracepcap.analysis.dto.segments;

import java.util.List;

/**
 * The networks a capture holds, told apart by their DHCP leases and IPv6 router advertisements
 * (#462 phase 1, #1357), and the ones that
 * use the same range. {@code unanswered} holds the clients nobody answered that no network could be
 * found for (no VLAN, or a VLAN no lease was handed out on).
 */
public record NetworkSegmentsResponse(
    List<Segment> segments, List<Overlap> overlaps, List<UnansweredClient> unanswered) {

  /**
   * One network: what identifies it and the clients it leased addresses to.
   *
   * @param key how it was told apart: vlan:N, server:MAC or id:IP|domain
   * @param label its domain, VLAN or DHCP server, for display
   * @param cidr its IPv4 range, from DHCPv4; null for an IPv6-only network
   * @param unanswered clients that asked for an address on this network (its VLAN) and got none
   * @param prefixes the IPv6 prefixes its routers advertised (#1357)
   * @param routerMacs the MACs of the IPv6 routers that advertised on it
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
      List<Client> clients,
      List<UnansweredClient> unanswered,
      List<String> prefixes,
      List<String> routerMacs) {}

  public record Client(String ip, String mac, String hostname) {}

  /**
   * A client that asked for an address and was never answered: its MAC, the name it asked under,
   * the VLAN it asked on, and how many times it asked.
   */
  public record UnansweredClient(String mac, String hostname, Integer vlanId, int requests) {}

  /** Networks whose ranges overlap, and the addresses leased on more than one of them. */
  public record Overlap(String cidr, List<String> segmentKeys, List<String> sharedAddresses) {}
}
