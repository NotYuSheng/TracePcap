package com.tracepcap.report;

import com.tracepcap.analysis.dto.occupancy.HostOccupancyResponse;
import com.tracepcap.analysis.dto.segments.NetworkSegmentsResponse;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What to call an address in the report: the name of the device that held it at that moment, the
 * network it's on, and for an internet address its organisation. An address two devices held in
 * turn is named by whichever held it at the time asked about, so a flagged conversation is pinned
 * on the right device.
 */
final class ReportNames {

  private final Map<String, HostFacts> hosts = new HashMap<>();
  private final Map<String, List<HostOccupancyResponse.Occupancy>> shared = new HashMap<>();
  private final Map<String, String> networkOf = new HashMap<>();
  private final List<NetworkSegmentsResponse.Segment> segments;
  private final Set<String> gateways = new HashSet<>();
  private final Map<String, String> orgs;

  ReportNames(
      List<HostFacts> hostFacts,
      List<HostOccupancyResponse.ReusedAddress> sharedAddresses,
      NetworkSegmentsResponse networks,
      Map<String, String> orgByIp) {
    for (HostFacts h : hostFacts) if (h.ip() != null) hosts.putIfAbsent(h.ip(), h);
    for (var r : sharedAddresses) shared.put(r.ip(), r.occupancies());
    this.segments = networks == null ? List.of() : networks.segments();
    for (var s : segments) {
      if (s.routers() != null) gateways.addAll(s.routers());
      if (s.routers() != null) s.routers().forEach(ip -> networkOf.put(ip, s.label()));
      for (var c : s.clients()) networkOf.put(c.ip(), s.label());
    }
    this.orgs = orgByIp == null ? Map.of() : orgByIp;
  }

  /** The device's name at that moment, or null when the capture never named it. */
  String name(String ip, LocalDateTime at) {
    if (ip == null) return null;
    var holders = shared.get(ip);
    if (holders != null) {
      var h = holderAt(holders, at);
      if (h != null) return h.getHostname() != null ? h.getHostname() : h.getMac();
    }
    HostFacts f = hosts.get(ip);
    if (f != null && f.hostname() != null && !f.hostname().isBlank()) return f.hostname();
    if (gateways.contains(ip)) return "Gateway";
    return null;
  }

  /** "LAPTOP-ANNA", else the address with its organisation for an internet host, else the address. */
  String label(String ip, LocalDateTime at) {
    String n = name(ip, at);
    if (n != null && !"Gateway".equals(n)) return n;
    if (n != null) return "Gateway " + ip;
    String org = shortOrg(orgs.get(ip));
    return org != null ? ip + " (" + org + ")" : String.valueOf(ip);
  }

  /** "Microsoft Corporation (AS8068)" → "Microsoft"; null for no organisation or an unknown one. */
  static String shortOrg(String org) {
    if (org == null) return null;
    String o = org.replaceAll("\\s*\\(AS\\d+\\)$", "").trim();
    if (o.toLowerCase().startsWith("unknown")) return null;
    return ReportService.vendor(o);
  }

  /** "Visitors-iPhone (10.20.20.51, guest.office.example (VLAN 20))", for a sentence. */
  String describe(String ip, LocalDateTime at) {
    String n = name(ip, at);
    String where = networkOf(ip);
    String org = shortOrg(orgs.get(ip));
    StringBuilder sb = new StringBuilder();
    sb.append(n != null ? n : ip);
    List<String> parts = new java.util.ArrayList<>();
    if (n != null) parts.add(ip);
    if (where != null) parts.add(where);
    else if (org != null) parts.add(org);
    if (!parts.isEmpty()) sb.append(" (").append(String.join(", ", parts)).append(")");
    return sb.toString();
  }

  /** The network an address is on, from DHCP, or null. */
  String networkOf(String ip) {
    String known = networkOf.get(ip);
    if (known != null) return known;
    for (var s : segments) if (s.cidr() != null && inCidr(ip, s.cidr())) return s.label();
    return null;
  }

  String org(String ip) {
    return orgs.get(ip);
  }

  boolean isGateway(String ip) {
    return gateways.contains(ip);
  }

  HostFacts facts(String ip) {
    return hosts.get(ip);
  }

  static HostOccupancyResponse.Occupancy holderAt(
      List<HostOccupancyResponse.Occupancy> holders, LocalDateTime at) {
    if (holders.isEmpty()) return null;
    if (at == null) return holders.get(0);
    for (var h : holders) {
      boolean started = h.getStartsAt() == null || !at.isBefore(h.getStartsAt());
      boolean notEnded = h.getEndsAt() == null || at.isBefore(h.getEndsAt());
      if (started && notEnded) return h;
    }
    return holders.get(holders.size() - 1);
  }

  /** Whether an IPv4 address falls in a CIDR range; false for anything it can't read. */
  static boolean inCidr(String ip, String cidr) {
    try {
      String[] parts = cidr.split("/");
      int bits = parts.length > 1 ? Integer.parseInt(parts[1]) : 32;
      long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
      return (v4(ip) & mask) == (v4(parts[0]) & mask);
    } catch (RuntimeException e) {
      return false;
    }
  }

  private static long v4(String ip) {
    String[] o = ip.split("\\.");
    if (o.length != 4) throw new IllegalArgumentException(ip);
    long v = 0;
    for (String s : o) v = (v << 8) | Integer.parseInt(s);
    return v;
  }
}
