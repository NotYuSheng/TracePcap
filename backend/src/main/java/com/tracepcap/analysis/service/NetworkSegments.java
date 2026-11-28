package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.DhcpLeaseEntity;
import com.tracepcap.analysis.entity.RouterAdvertEntity;
import com.tracepcap.common.net.Cidr;
import com.tracepcap.common.net.CidrBlock;
import com.tracepcap.common.net.IpLocality;
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
 * <p>IPv6 (#1357) joins the same way: a router's advertisements and its DHCPv6 leases are keyed
 * by their VLAN, else by the router's MAC, so a dual-stack VLAN (or a router serving both DHCPv4
 * and IPv6) is one segment with an IPv4 range and its IPv6 prefixes.
 *
 * <p>Two segments <b>overlap</b> when their ranges intersect: two networks using the same addresses,
 * as at two sites or on two VLANs. Then an address used on both (leased, or a router's) is two
 * machines, not one. In IPv6 every link has the same link-local range, so two segments also
 * overlap when one link-local address (two routers both at {@code fe80::1}) is used on both.
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
      List<Client> clients,
      Set<String> prefixes,
      Map<String, String> routerMacs) {

    /** Its ranges: the IPv4 range, then the IPv6 prefixes its router advertised. */
    public List<String> ranges() {
      List<String> out = new ArrayList<>();
      if (cidr != null) out.add(cidr);
      out.addAll(prefixes);
      return out;
    }

    /** Whether {@code ip} is in one of its ranges. */
    public boolean covers(String ip) {
      return ranges().stream().anyMatch(r -> CidrBlock.contains(r, ip));
    }
  }

  public record Client(String ip, String mac, String hostname) {}

  /** One machine on a shared address: which network, and its MAC and hostname there. */
  public record NetDevice(String segmentKey, String label, String mac, String hostname) {}

  /** Networks whose ranges overlap, and the addresses leased in more than one of them. */
  public record Overlap(String cidr, List<String> segmentKeys, List<String> sharedAddresses) {}

  public record Result(List<Segment> segments, List<Overlap> overlaps) {

    /** The segment each client MAC was leased an address in. */
    public Map<String, String> segmentByMac() {
      Map<String, String> out = new LinkedHashMap<>();
      for (Segment s : segments) for (Client c : s.clients()) out.put(c.mac(), s.key());
      return out;
    }

    /**
     * For each address used on more than one overlapping network, the machine on each (#462 phase
     * 2a): the network's key and label, and the machine's MAC and hostname there. A router's address
     * has the router's MAC. Networks in the order they were found.
     */
    public Map<String, List<NetDevice>> devicesOnSeveralNetworks() {
      Map<String, Segment> byKey = new LinkedHashMap<>();
      segments.forEach(s -> byKey.put(s.key(), s));
      Map<String, List<NetDevice>> out = new LinkedHashMap<>();
      for (Overlap o : overlaps) {
        for (String ip : o.sharedAddresses()) {
          List<NetDevice> devices = new ArrayList<>();
          for (String k : o.segmentKeys()) {
            Segment s = byKey.get(k);
            if (s == null) continue;
            Client c = s.clients().stream().filter(x -> x.ip().equals(ip)).findFirst().orElse(null);
            if (c != null) devices.add(new NetDevice(s.key(), s.label(), c.mac(), c.hostname()));
            else if (s.routers().contains(ip)) {
              devices.add(new NetDevice(s.key(), s.label(), s.routerMacs().getOrDefault(ip, s.serverMac()), null));
            }
          }
          if (devices.size() > 1) out.put(ip, devices);
        }
      }
      return out;
    }

    /** The MACs seen on each network: its DHCP clients', its server's and its routers'. */
    public Map<String, Set<String>> macsBySegment() {
      Map<String, Set<String>> out = new LinkedHashMap<>();
      for (Segment s : segments) {
        Set<String> macs = new LinkedHashSet<>();
        if (s.serverMac() != null) macs.add(s.serverMac());
        macs.addAll(s.routerMacs().values());
        s.clients().forEach(c -> macs.add(c.mac()));
        out.put(s.key(), macs);
      }
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
    final Set<String> prefixes = new TreeSet<>();
    final Map<String, String> routerMacs = new LinkedHashMap<>();
    String mask;
    java.time.LocalDateTime firstLease;
    final Map<String, Client> clients = new LinkedHashMap<>();

    Acc(String key) {
      this.key = key;
    }
  }

  public static Result of(List<DhcpLeaseEntity> leases) {
    return of(leases, List.of());
  }

  public static Result of(List<DhcpLeaseEntity> leases, List<RouterAdvertEntity> adverts) {
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
      noteFirst(a, l.getFirstSeen());
      a.clients.put(clientKey(l.getMac(), l.getIp()), new Client(l.getIp(), l.getMac(), l.getHostname()));
      keyByMac.put(l.getMac(), key);
    }
    for (RouterAdvertEntity ra : adverts) {
      String key = ra.getVlanId() != null ? "vlan:" + ra.getVlanId() : "server:" + ra.getRouterMac();
      Acc a = byKey.computeIfAbsent(key, Acc::new);
      if (ra.getVlanId() != null) a.vlanId = ra.getVlanId();
      if (ra.getRouterIp() != null) {
        a.routers.add(ra.getRouterIp());
        a.routerMacs.put(ra.getRouterIp(), ra.getRouterMac());
      }
      if (ra.getPrefixes() != null) a.prefixes.addAll(List.of(ra.getPrefixes()));
      if (ra.getDomain() != null) a.domains.add(ra.getDomain());
      noteFirst(a, ra.getFirstSeen());
    }
    for (DhcpLeaseEntity l : unacked) {
      String key = keyByMac.get(l.getMac());
      if (key == null) continue;
      Acc a = byKey.get(key);
      String ck = clientKey(l.getMac(), l.getIp());
      Client prev = a.clients.get(ck);
      String hostname = l.getHostname() != null ? l.getHostname() : prev == null ? null : prev.hostname();
      a.clients.put(ck, new Client(prev != null ? prev.ip() : l.getIp(), l.getMac(), hostname));
    }

    // Networks in the order they first leased an address (then by key), so which network's machine
    // keeps an address's bare key is stable from run to run.
    List<Acc> ordered = new ArrayList<>(byKey.values());
    ordered.sort(
        Comparator.comparing((Acc a) -> a.firstLease, Comparator.nullsLast(Comparator.naturalOrder()))
            .thenComparing(a -> a.key));
    List<Segment> segments = new ArrayList<>();
    for (Acc a : ordered) {
      List<Client> clients = new ArrayList<>(a.clients.values());
      clients.sort(Comparator.comparing(Client::ip, Cidr.ADDRESS_ORDER));
      Set<String> routers = new TreeSet<>(Cidr.ADDRESS_ORDER);
      routers.addAll(a.routers);
      segments.add(
          new Segment(a.key, label(a), a.vlanId, a.serverMac, a.serverIds, routers, a.domains,
              a.leaseSeconds, cidr(clients, a.mask),
              clients, a.prefixes, a.routerMacs));
    }
    return new Result(segments, overlaps(segments));
  }

  private static void noteFirst(Acc a, java.time.LocalDateTime at) {
    if (at != null && (a.firstLease == null || at.isBefore(a.firstLease))) a.firstLease = at;
  }

  /** A client is one per MAC and family: a dual-stack machine has an IPv4 and an IPv6 lease. */
  private static String clientKey(String mac, String ip) {
    byte[] b = Cidr.addressBytes(ip);
    return mac + (b != null && b.length == 16 ? "|6" : "|4");
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
            : !a.serverIds.isEmpty() ? "DHCP server " + String.join(", ", a.serverIds)
            : "Router " + String.join(", ", new TreeSet<>(a.routerMacs.values()));
    return a.vlanId != null && !a.domains.isEmpty() ? base + " (VLAN " + a.vlanId + ")" : base;
  }

  private static List<Overlap> overlaps(List<Segment> segments) {
    // Group segments whose ranges intersect, then list addresses leased in more than one of them.
    List<List<Segment>> groups = new ArrayList<>();
    for (Segment s : segments) {
      List<Segment> joined = null;
      for (List<Segment> g : groups) {
        if (g.stream().anyMatch(o -> overlap(o, s))) {
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
      shared.sort(Cidr.ADDRESS_ORDER);
      out.add(new Overlap(sharedRange(g), g.stream().map(Segment::key).toList(), shared));
    }
    return out;
  }

  /**
   * Whether two networks use the same addresses: their IPv4 ranges or IPv6 prefixes intersect, or
   * one link-local address is used on both (every link has the whole link-local range).
   */
  static boolean overlap(Segment a, Segment b) {
    for (String x : a.ranges()) for (String y : b.ranges()) if (intersects(x, y)) return true;
    Set<String> linkLocal = linkLocal(a);
    linkLocal.retainAll(linkLocal(b));
    return !linkLocal.isEmpty();
  }

  private static Set<String> linkLocal(Segment s) {
    Set<String> out = new LinkedHashSet<>();
    s.routers().stream().filter(IpLocality::isLinkLocal).forEach(out::add);
    s.clients().stream().map(Client::ip).filter(IpLocality::isLinkLocal).forEach(out::add);
    return out;
  }

  /**
   * The range a group of overlapping networks shares: the widest range that intersects another
   * network's, IPv4 first; else link-local, which is what they share when no range intersects.
   */
  private static String sharedRange(List<Segment> g) {
    List<String> shared = new ArrayList<>();
    for (Segment a : g) {
      for (String x : a.ranges()) {
        boolean another = g.stream().anyMatch(b -> b != a && b.ranges().stream().anyMatch(y -> intersects(x, y)));
        if (another) shared.add(x);
      }
    }
    return shared.stream()
        .min(Comparator.comparing((String r) -> !r.contains("."))
            .thenComparingInt(NetworkSegments::prefix)
            .thenComparing(r -> r))
        .orElse(LINK_LOCAL);
  }

  static final String LINK_LOCAL = "fe80::/64";

  // ── Ranges ───────────────────────────────────────────────────────────────────

  /**
   * The segment's IPv4 range: from its subnet mask when DHCP gave one, else the /24 of its first
   * IPv4 client. Null with no IPv4 client.
   */
  static String cidr(List<Client> clients, String mask) {
    String first = clients.stream().map(Client::ip).filter(NetworkSegments::isIpv4).findFirst().orElse(null);
    if (first == null) return null;
    int prefix = mask == null ? 24 : maskPrefix(mask);
    return CidrBlock.parse(first + "/" + prefix).map(CidrBlock::toString).orElse(null);
  }

  /** Whether two ranges (IPv4 or IPv6) share addresses: one holds the other's first address. */
  static boolean intersects(String a, String b) {
    if (a == null || b == null || a.indexOf('/') < 0 || b.indexOf('/') < 0) return false;
    return CidrBlock.contains(a, b.substring(0, b.indexOf('/'))) || CidrBlock.contains(b, a.substring(0, a.indexOf('/')));
  }

  private static int prefix(String cidr) {
    return Integer.parseInt(cidr.substring(cidr.indexOf('/') + 1));
  }

  /** A dotted mask's prefix length ({@code 255.255.255.0} → 24); 24 when it isn't one. */
  static int maskPrefix(String mask) {
    byte[] b = Cidr.addressBytes(mask);
    if (b == null || b.length != 4) return 24;
    int n = 0;
    for (byte x : b) n += Integer.bitCount(x & 0xFF);
    return n;
  }

  private static boolean isIpv4(String ip) {
    byte[] b = Cidr.addressBytes(ip);
    return b != null && b.length == 4;
  }
}
