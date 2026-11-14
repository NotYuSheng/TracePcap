package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.DhcpLeaseEntity;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Tells apart the networks a capture holds from its DHCP leases (#462 phase 1). Pure, so analysis
 * and the read API share one rule.
 *
 * <p>A <b>segment</b> is the set of leases one network handed out. Leases are grouped by the 802.1Q
 * VLAN their ACK was tagged with when there is one, else by the DHCP server's MAC (two routers both
 * at 192.168.1.1 have different MACs), else by the server identifier and domain. A REQUEST with no
 * ACK joins the segment its client was ACKed in.
 *
 * <p>Two segments <b>overlap</b> when their ranges intersect: two networks using the same addresses,
 * as at two sites or on two VLANs. Then an address used on both (leased, or a router's) is two
 * machines, not one.
 */
public final class NetworkSegments {

  private NetworkSegments() {}

  /** One network, with what identifies it and the clients it leased to. */
  public record Segment(
      String key,
      String label,
      Integer vlanId,
      String serverMac,
      Set<String> serverIds,
      Set<String> routers,
      Set<String> domains,
      Set<Long> leaseSeconds,
      String cidr,
      List<Client> clients) {}

  public record Client(String ip, String mac, String hostname) {}

  /** Networks whose ranges overlap, and the addresses leased in more than one of them. */
  public record Overlap(String cidr, List<String> segmentKeys, List<String> sharedAddresses) {}

  public record Result(List<Segment> segments, List<Overlap> overlaps) {

    /** The segment each client MAC was leased an address in. */
    public Map<String, String> segmentByMac() {
      Map<String, String> out = new LinkedHashMap<>();
      for (Segment s : segments) for (Client c : s.clients()) out.put(c.mac(), s.key());
      return out;
    }

    /** For each address leased on more than one overlapping network, those networks' labels. */
    public Map<String, List<String>> addressesOnSeveralNetworks() {
      Map<String, Segment> byKey = new LinkedHashMap<>();
      segments.forEach(s -> byKey.put(s.key(), s));
      Map<String, List<String>> out = new LinkedHashMap<>();
      for (Overlap o : overlaps) {
        for (String ip : o.sharedAddresses()) {
          List<String> labels = new ArrayList<>();
          for (String k : o.segmentKeys()) {
            Segment s = byKey.get(k);
            if (s != null && (s.routers().contains(ip) || s.clients().stream().anyMatch(c -> c.ip().equals(ip)))) {
              labels.add(s.label());
            }
          }
          out.put(ip, labels);
        }
      }
      return out;
    }
  }

  private static final class Acc {
    final String key;
    Integer vlanId;
    String serverMac;
    final Set<String> serverIds = new TreeSet<>();
    final Set<String> routers = new TreeSet<>();
    final Set<String> domains = new TreeSet<>();
    final Set<Long> leaseSeconds = new TreeSet<>();
    String mask;
    final Map<String, Client> clients = new LinkedHashMap<>();

    Acc(String key) {
      this.key = key;
    }
  }

  public static Result of(List<DhcpLeaseEntity> leases) {
    Map<String, Acc> byKey = new LinkedHashMap<>();
    Map<String, String> keyByMac = new LinkedHashMap<>();
    List<DhcpLeaseEntity> unacked = new ArrayList<>();
    for (DhcpLeaseEntity l : leases) {
      String key = key(l);
      if (key == null) {
        unacked.add(l);
        continue;
      }
      Acc a = byKey.computeIfAbsent(key, Acc::new);
      if (l.getVlanId() != null) a.vlanId = l.getVlanId();
      if (l.getServerMac() != null) a.serverMac = l.getServerMac();
      if (l.getServerId() != null) a.serverIds.add(l.getServerId());
      if (l.getRouter() != null) a.routers.add(l.getRouter());
      if (l.getDomain() != null) a.domains.add(l.getDomain());
      if (l.getLeaseSeconds() != null) a.leaseSeconds.add(l.getLeaseSeconds());
      if (l.getSubnetMask() != null) a.mask = l.getSubnetMask();
      a.clients.put(l.getMac(), new Client(l.getIp(), l.getMac(), l.getHostname()));
      keyByMac.put(l.getMac(), key);
    }
    for (DhcpLeaseEntity l : unacked) {
      String key = keyByMac.get(l.getMac());
      if (key == null) continue;
      Acc a = byKey.get(key);
      Client prev = a.clients.get(l.getMac());
      String hostname = l.getHostname() != null ? l.getHostname() : prev == null ? null : prev.hostname();
      a.clients.put(l.getMac(), new Client(prev != null ? prev.ip() : l.getIp(), l.getMac(), hostname));
    }

    List<Segment> segments = new ArrayList<>();
    for (Acc a : byKey.values()) {
      List<Client> clients = new ArrayList<>(a.clients.values());
      clients.sort(Comparator.comparingLong(c -> ipValue(c.ip())));
      segments.add(
          new Segment(a.key, label(a), a.vlanId, a.serverMac, a.serverIds, a.routers, a.domains,
              a.leaseSeconds, cidr(clients, a.mask), clients));
    }
    return new Result(segments, overlaps(segments));
  }

  /** What makes a lease's network itself: its VLAN, else its server's MAC, else server and domain. */
  static String key(DhcpLeaseEntity l) {
    if (l.getVlanId() != null) return "vlan:" + l.getVlanId();
    if (l.getServerMac() != null) return "server:" + l.getServerMac();
    if (l.getServerId() != null) return "id:" + l.getServerId() + "|" + (l.getDomain() == null ? "" : l.getDomain());
    return null;
  }

  private static String label(Acc a) {
    String base =
        !a.domains.isEmpty() ? a.domains.iterator().next()
            : a.vlanId != null ? "VLAN " + a.vlanId
            : a.serverMac != null ? "DHCP server " + a.serverMac
            : "DHCP server " + String.join(", ", a.serverIds);
    return a.vlanId != null && !a.domains.isEmpty() ? base + " (VLAN " + a.vlanId + ")" : base;
  }

  private static List<Overlap> overlaps(List<Segment> segments) {
    // Group segments whose ranges intersect, then list addresses leased in more than one of them.
    List<List<Segment>> groups = new ArrayList<>();
    for (Segment s : segments) {
      List<Segment> joined = null;
      for (List<Segment> g : groups) {
        if (g.stream().anyMatch(o -> intersects(o.cidr(), s.cidr()))) {
          if (joined == null) {
            g.add(s);
            joined = g;
          } else {
            joined.addAll(g);
            g.clear();
          }
        }
      }
      groups.removeIf(List::isEmpty);
      if (joined == null) groups.add(new ArrayList<>(List.of(s)));
    }
    List<Overlap> out = new ArrayList<>();
    for (List<Segment> g : groups) {
      if (g.size() < 2) continue;
      Map<String, Integer> uses = new LinkedHashMap<>();
      for (Segment s : g) {
        // The clients it leased to, and its router: two sites' routers are often both .1.
        Set<String> ips = new LinkedHashSet<>(s.routers());
        s.clients().forEach(c -> ips.add(c.ip()));
        ips.forEach(ip -> uses.merge(ip, 1, Integer::sum));
      }
      List<String> shared = new ArrayList<>();
      uses.forEach((ip, n) -> { if (n > 1) shared.add(ip); });
      shared.sort(Comparator.comparingLong(NetworkSegments::ipValue));
      String widest = g.stream().map(Segment::cidr).min(Comparator.comparingInt(NetworkSegments::prefix)).orElse(null);
      out.add(new Overlap(widest, g.stream().map(Segment::key).toList(), shared));
    }
    return out;
  }

  // ── IPv4 arithmetic (DHCP here is v4) ────────────────────────────────────────

  /** The segment's CIDR: from its subnet mask when DHCP gave one, else the /24 of its first client. */
  static String cidr(List<Client> clients, String mask) {
    if (clients.isEmpty()) return null;
    long ip = ipValue(clients.get(0).ip());
    if (ip < 0) return null;
    int prefix = mask == null ? 24 : maskPrefix(mask);
    long net = prefix == 0 ? 0 : ip & (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
    return ipString(net) + "/" + prefix;
  }

  static boolean intersects(String a, String b) {
    if (a == null || b == null) return false;
    long na = ipValue(a.substring(0, a.indexOf('/')));
    long nb = ipValue(b.substring(0, b.indexOf('/')));
    int p = Math.min(prefix(a), prefix(b));
    long m = p == 0 ? 0 : (0xFFFFFFFFL << (32 - p)) & 0xFFFFFFFFL;
    return (na & m) == (nb & m);
  }

  private static int prefix(String cidr) {
    return Integer.parseInt(cidr.substring(cidr.indexOf('/') + 1));
  }

  static int maskPrefix(String mask) {
    long m = ipValue(mask);
    return m < 0 ? 24 : Long.bitCount(m);
  }

  static long ipValue(String ip) {
    if (ip == null) return -1;
    String[] p = ip.split("\\.");
    if (p.length != 4) return -1;
    long v = 0;
    try {
      for (String part : p) {
        int o = Integer.parseInt(part);
        if (o < 0 || o > 255) return -1;
        v = (v << 8) | o;
      }
    } catch (NumberFormatException e) {
      return -1;
    }
    return v;
  }

  private static String ipString(long v) {
    return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
  }
}
