package com.tracepcap.analysis.service;

import com.tracepcap.common.net.IpLocality;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Finds DHCP leases (#918 item 3): which client MAC was given, or asked for, which address and
 * when. A different MAC on the same address later in the capture is evidence that the address
 * passed to another device.
 *
 * <ul>
 *   <li><b>ACK</b> (type 5): the server hands {@code yiaddr} (or confirms {@code ciaddr}) to
 *       {@code chaddr}.
 *   <li><b>REQUEST</b> (type 3): the client asks for an address (option 50, or {@code ciaddr} when
 *       renewing) and usually names itself (option 12).
 * </ul>
 *
 * <p>IPv6 (#1357) in the same pass: a DHCPv6 <b>Reply</b> (type 7) hands the client its addresses
 * (IA Address, option 5) and is a lease like an ACK, with the client's MAC from the frame it was
 * sent to. A <b>Router Advertisement</b> (ICMPv6 134) is how most IPv6 networks give out addresses
 * (SLAAC): it names the router (its MAC and link-local address), the network's prefixes and
 * often its DNS search domain, and is an {@link Advert}.
 *
 * Reads only the capture, so it runs in the tool stage with no database connection. Never throws.
 */
@Slf4j
@Service
public class DhcpLeaseResolverService {

  /**
   * One (ip, client MAC) lease with its first and last time and the hostname asked under, plus the
   * client's DHCP fingerprint (#918 slice 4b): the options it asked for, in order (option 55), and
   * its vendor class (option 60). The fingerprint names the client's OS and often its model, and
   * stays the same when a phone changes its private MAC.
   */
  public record Lease(
      String ip, String mac, String hostname, LocalDateTime firstSeen, LocalDateTime lastSeen,
      String fingerprint, String vendorClass, Network network) {

    public Lease(String ip, String mac, String hostname, LocalDateTime firstSeen, LocalDateTime lastSeen) {
      this(ip, mac, hostname, firstSeen, lastSeen, null, null, null);
    }

    public Lease(
        String ip, String mac, String hostname, LocalDateTime firstSeen, LocalDateTime lastSeen,
        String fingerprint, String vendorClass) {
      this(ip, mac, hostname, firstSeen, lastSeen, fingerprint, vendorClass, null);
    }
  }

  /**
   * Which network the lease came from (#462), from the server's ACK: the server's MAC and
   * identifier (option 54), the router (3), domain (15), lease time in seconds (51), subnet mask (1),
   * and the 802.1Q VLAN the ACK was tagged with. Two networks using one range differ here.
   */
  public record Network(
      String serverMac, String serverId, String router, String domain, Long leaseSeconds,
      String subnetMask, Integer vlanId) {}

  /**
   * A client that asked for an address (DISCOVER or REQUEST) and was never answered with an ACK:
   * it has no address, so its MAC, the name it asked under and the VLAN it asked on identify it.
   */
  public record Unanswered(
      String mac, String hostname, String vendorClass, Integer vlanId, int requests,
      LocalDateTime firstSeen, LocalDateTime lastSeen) {}

  /**
   * One router's advertisements (#1357): its MAC, its (link-local) address, the VLAN they were
   * tagged with, the prefixes it advertised (normalised CIDRs) and its DNS search domain.
   */
  public record Advert(
      String routerMac, String routerIp, Integer vlanId, List<String> prefixes, String domain,
      LocalDateTime firstSeen, LocalDateTime lastSeen) {}

  /** Everything one pass over the capture's DHCP and router advertisements finds. */
  public record Resolution(List<Lease> leases, List<Unanswered> unanswered, List<Advert> adverts) {

    public Resolution(List<Lease> leases, List<Unanswered> unanswered) {
      this(leases, unanswered, List.of());
    }
  }

  /** What one MAC's requests have shown so far, while the pass runs. */
  static final class Asking {
    String hostname;
    String vendorClass;
    Integer vlanId;
    int requests;
    LocalDateTime first;
    LocalDateTime last;
  }

  public List<Lease> resolve(File pcapFile) {
    return resolveAll(pcapFile).leases();
  }

  public Resolution resolveAll(File pcapFile) {
    Map<String, Lease> leases = new LinkedHashMap<>();
    Map<String, Asking> asking = new LinkedHashMap<>();
    java.util.Set<String> acked = new java.util.HashSet<>();
    Map<String, Advert> adverts = new LinkedHashMap<>();
    ProcessBuilder pb =
        new ProcessBuilder(
            "tshark",
            "-r",
            pcapFile.getAbsolutePath(),
            "-Y",
            // DISCOVER too: a client nobody answers may never get past it.
            "dhcp.option.dhcp == 1 || dhcp.option.dhcp == 3 || dhcp.option.dhcp == 5"
                // IPv6 (#1357): router advertisements and DHCPv6 replies.
                + " || icmpv6.type == 134 || dhcpv6.msgtype == 7",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            // Every occurrence, so option 55's list comes through whole; the single-valued fields
            // take their first.
            "occurrence=a",
            "-E",
            "aggregator=;",
            "-e",
            "frame.time_epoch",
            "-e",
            "dhcp.option.dhcp",
            "-e",
            "dhcp.ip.your",
            "-e",
            "dhcp.ip.client",
            "-e",
            "dhcp.option.requested_ip_address",
            "-e",
            "dhcp.hw.mac_addr",
            "-e",
            "dhcp.option.hostname",
            "-e",
            "dhcp.option.request_list_item",
            "-e",
            "dhcp.option.vendor_class_id",
            "-e",
            "eth.src",
            "-e",
            "dhcp.option.dhcp_server_id",
            "-e",
            "dhcp.option.router",
            "-e",
            "dhcp.option.domain_name",
            "-e",
            "dhcp.option.ip_address_lease_time",
            "-e",
            "dhcp.option.subnet_mask",
            "-e",
            "vlan.id",
            // 16–27: IPv6, read by parseIpv6Row.
            "-e",
            "icmpv6.type",
            "-e",
            "ipv6.src",
            "-e",
            "eth.dst",
            "-e",
            "icmpv6.opt.prefix",
            "-e",
            "icmpv6.opt.prefix.length",
            "-e",
            "icmpv6.opt.dnssl",
            "-e",
            "dhcpv6.msgtype",
            "-e",
            "dhcpv6.iaaddr.ip",
            "-e",
            "dhcpv6.iaaddr.valid_lifetime",
            "-e",
            "dhcpv6.client_domain",
            "-e",
            "dhcpv6.search_list_entry",
            "-e",
            "icmpv6.opt.type");
    pb.redirectErrorStream(false);

    Process process = null;
    ExecutorService ioExecutor = null;
    try {
      process = pb.start();
      final Process proc = process;
      Thread stderrThread =
          new Thread(
              () -> {
                try (BufferedReader err =
                    new BufferedReader(new InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8))) {
                  while (err.readLine() != null) {
                    // discard
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });
      stderrThread.setDaemon(true);
      stderrThread.start();

      ioExecutor = Executors.newSingleThreadExecutor();
      Future<?> stdoutTask =
          ioExecutor.submit(
              () -> {
                try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                  String line;
                  while ((line = reader.readLine()) != null) {
                    synchronized (leases) {
                      String[] f = line.split("\\|", -1);
                      if (!parseIpv6Row(f, leases, adverts)) parseRow(f, leases, asking, acked);
                    }
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });

      if (!process.waitFor(2, TimeUnit.MINUTES)) {
        log.warn("DHCP lease resolution timed out; returning partial results");
      } else {
        try {
          stdoutTask.get(5, TimeUnit.SECONDS);
        } catch (Exception ignored) {
          // best-effort
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      log.warn("DHCP lease resolution failed: {}", e.getMessage());
    } finally {
      if (process != null) process.destroyForcibly();
      if (ioExecutor != null) ioExecutor.shutdownNow();
    }
    synchronized (leases) {
      if (!leases.isEmpty()) log.info("Found {} DHCP lease(s)", leases.size());
      List<Unanswered> unanswered = unanswered(asking, acked, leases);
      if (!unanswered.isEmpty()) log.info("Found {} unanswered DHCP client(s)", unanswered.size());
      if (!adverts.isEmpty()) log.info("Found {} IPv6 router(s) advertising", adverts.size());
      return new Resolution(new ArrayList<>(leases.values()), unanswered, new ArrayList<>(adverts.values()));
    }
  }

  /** The MACs that asked but were never ACKed and hold no lease (not even from a lone REQUEST). */
  static List<Unanswered> unanswered(
      Map<String, Asking> asking, java.util.Set<String> acked, Map<String, Lease> leases) {
    java.util.Set<String> leased = new java.util.HashSet<>();
    // DHCPv4's: a DHCPv6 lease doesn't answer a client's DHCPv4 requests.
    for (Lease l : leases.values()) {
      byte[] b = com.tracepcap.common.net.Cidr.addressBytes(l.ip());
      if (b != null && b.length == 4) leased.add(l.mac());
    }
    List<Unanswered> out = new ArrayList<>();
    asking.forEach(
        (mac, a) -> {
          if (acked.contains(mac) || leased.contains(mac)) return;
          out.add(new Unanswered(mac, a.hostname, a.vendorClass, a.vlanId, a.requests, a.first, a.last));
        });
    return out;
  }

  /**
   * Folds one tshark row into {@code leases}. Fields: epoch, message type, yiaddr, ciaddr,
   * requested address, chaddr, hostname.
   */
  static void parseRow(String[] f, Map<String, Lease> leases) {
    parseRow(f, leases, new LinkedHashMap<>(), new java.util.HashSet<>());
  }

  /**
   * As {@link #parseRow(String[], Map)}, also noting each client's requests in {@code asking} and
   * each MAC an ACK went to in {@code acked}, which together give the clients nobody answered.
   */
  static void parseRow(
      String[] f, Map<String, Lease> leases, Map<String, Asking> asking, java.util.Set<String> acked) {
    if (f.length < 7) return;
    // Fields 0–6 hold one value each; with every occurrence on, keep the first.
    String fingerprint = f.length > 7 && !f[7].isBlank() ? f[7].trim().replace(';', ',') : null;
    if (fingerprint != null && fingerprint.length() > 255) fingerprint = fingerprint.substring(0, 255);
    String vendorClass = f.length > 8 && !f[8].isBlank() ? first(f[8]) : null;
    if (vendorClass != null && vendorClass.length() > 255) vendorClass = vendorClass.substring(0, 255);
    f = java.util.Arrays.stream(f).map(DhcpLeaseResolverService::first).toArray(String[]::new);
    // The network the server's ACK names (#462); a REQUEST's eth.src is the client, so ACKs only.
    Network network = "5".equals(f[1].trim()) && f.length > 15 ? network(f) : null;
    LocalDateTime at;
    try {
      double epoch = Double.parseDouble(f[0].trim());
      at = LocalDateTime.ofInstant(Instant.ofEpochMilli((long) (epoch * 1000)), ZoneId.systemDefault());
    } catch (NumberFormatException e) {
      return;
    }
    String type = f[1].trim();
    noteAsking(f, type, at, vendorClass, asking, acked);
    String ip =
        switch (type) {
          case "5" ->
              IpLocality.isAssigned(f[2]) ? f[2].trim() : IpLocality.isAssigned(f[3]) ? f[3].trim() : null;
          case "3" ->
              IpLocality.isAssigned(f[4]) ? f[4].trim() : IpLocality.isAssigned(f[3]) ? f[3].trim() : null;
          default -> null;
        };
    String mac = f[5].trim().toLowerCase();
    if (ip == null || ip.length() > 45 || mac.isEmpty() || mac.length() > 50) return;
    String hostname = f[6].trim();
    if (hostname.isEmpty()) hostname = null;
    else if (hostname.length() > 255) hostname = hostname.substring(0, 255);

    String key = ip + "|" + mac;
    Lease prev = leases.get(key);
    if (prev == null) {
      leases.put(key, new Lease(ip, mac, hostname, at, at, fingerprint, vendorClass, network));
    } else {
      leases.put(
          key,
          new Lease(
              ip,
              mac,
              hostname != null ? hostname : prev.hostname(),
              at.isBefore(prev.firstSeen()) ? at : prev.firstSeen(),
              at.isAfter(prev.lastSeen()) ? at : prev.lastSeen(),
              fingerprint != null ? fingerprint : prev.fingerprint(),
              vendorClass != null ? vendorClass : prev.vendorClass(),
              network != null ? network : prev.network()));
    }
  }

  /**
   * Folds one row into {@code leases} or {@code adverts} when it is a DHCPv6 Reply or a Router
   * Advertisement (fields 16–27), and says whether it was. The outer message decides: an ICMPv6
   * error quoting an RA, or a relay's Relay-Reply carrying a Reply, is not one.
   */
  static boolean parseIpv6Row(String[] f, Map<String, Lease> leases, Map<String, Advert> adverts) {
    if (f.length < 28) return false;
    boolean ra = "134".equals(first(f[16]));
    // A Reply only as the packet itself: an ICMPv6 error quoting one (sent back to the server) has
    // an outer ICMPv6 type, and its destination is the server, not the client.
    boolean reply = "7".equals(first(f[22])) && blank(f[16]);
    if (!ra && !reply) return false;
    LocalDateTime at;
    try {
      double epoch = Double.parseDouble(first(f[0]));
      at = LocalDateTime.ofInstant(Instant.ofEpochMilli((long) (epoch * 1000)), ZoneId.systemDefault());
    } catch (NumberFormatException e) {
      return true;
    }
    String from = first(f[9]).toLowerCase();
    String fromIp = cut(first(f[17]), 45);
    Integer vlan = null;
    try {
      if (!blank(first(f[15]))) vlan = Integer.parseInt(first(f[15]));
    } catch (NumberFormatException ignored) {
      // not a VLAN id
    }
    if (from.isEmpty() || from.length() > 50) return true;
    if (ra) {
      List<String> prefixes = new ArrayList<>();
      String[] ps = all(f[19]);
      String[] lens = all(f[20]);
      // Prefix Information (3) and Route Information (24) options both write these fields, in
      // option order; only a PIO is this link's prefix (an RIO is a route to somewhere else).
      List<String> carriers =
          java.util.Arrays.stream(all(f[27])).filter(t -> t.equals("3") || t.equals("24")).toList();
      boolean aligned = carriers.size() == ps.length && ps.length == lens.length;
      for (int i = 0; aligned && i < ps.length; i++) {
        if (!carriers.get(i).equals("3")) continue;
        var block = com.tracepcap.common.net.CidrBlock.parse(ps[i] + "/" + lens[i]);
        // A network's own prefix: not link-local (every link has fe80::/64) and not a whole family.
        if (block.isEmpty() || block.get().isIpv4() || block.get().prefix() == 0) continue;
        if (IpLocality.isLinkLocal(ps[i])) continue;
        prefixes.add(block.get().toString());
      }
      String domain = domain(first(f[21]));
      String key = from + "|" + fromIp + "|" + vlan;
      Advert prev = adverts.get(key);
      if (prev == null) {
        adverts.put(key, new Advert(from, fromIp, vlan, prefixes, domain, at, at));
      } else {
        java.util.Set<String> merged = new java.util.LinkedHashSet<>(prev.prefixes());
        merged.addAll(prefixes);
        adverts.put(
            key,
            new Advert(from, fromIp, vlan, new ArrayList<>(merged), prev.domain() != null ? prev.domain() : domain,
                at.isBefore(prev.firstSeen()) ? at : prev.firstSeen(),
                at.isAfter(prev.lastSeen()) ? at : prev.lastSeen()));
      }
      return true;
    }
    // A Reply goes to the client: the frame's destination is its MAC (never a group address).
    String mac = first(f[18]).toLowerCase();
    if (mac.isEmpty() || mac.length() > 50 || com.tracepcap.common.net.MacAddress.isGroup(mac)) return true;
    String fqdn = domain(first(f[25]));
    String hostname = fqdn == null ? null : cut(fqdn.contains(".") ? fqdn.substring(0, fqdn.indexOf('.')) : fqdn, 255);
    String domain = domain(first(f[26]));
    if (domain == null && fqdn != null && fqdn.contains(".")) domain = domain(fqdn.substring(fqdn.indexOf('.') + 1));
    String[] ips = all(f[23]);
    String[] lifetimes = all(f[24]);
    for (int i = 0; i < ips.length; i++) {
      String ip = ips[i];
      byte[] b = com.tracepcap.common.net.Cidr.addressBytes(ip);
      if (b == null || b.length != 16 || !IpLocality.isAssigned(ip) || ip.length() > 45) continue;
      Long lease = null;
      try {
        if (i < lifetimes.length) lease = Long.parseLong(lifetimes[i]);
      } catch (NumberFormatException ignored) {
        // leave it unknown
      }
      Network network = new Network(from, fromIp, null, domain, lease, null, vlan);
      String key = ip + "|" + mac;
      Lease prev = leases.get(key);
      leases.put(
          key,
          prev == null
              ? new Lease(ip, mac, hostname, at, at, null, null, network)
              : new Lease(ip, mac, hostname != null ? hostname : prev.hostname(),
                  at.isBefore(prev.firstSeen()) ? at : prev.firstSeen(),
                  at.isAfter(prev.lastSeen()) ? at : prev.lastSeen(), null, null, network));
    }
    return true;
  }

  /** A domain as written in DNS (trailing dot dropped), or null. */
  private static String domain(String s) {
    if (blank(s)) return null;
    String d = s.trim();
    if (d.endsWith(".")) d = d.substring(0, d.length() - 1);
    return d.isEmpty() ? null : cut(d, 255);
  }

  /** Every value of an aggregated field. */
  private static String[] all(String field) {
    if (blank(field)) return new String[0];
    return java.util.Arrays.stream(field.split(";")).map(String::trim).filter(x -> !x.isEmpty()).toArray(String[]::new);
  }

  private static void noteAsking(
      String[] f, String type, LocalDateTime at, String vendorClass,
      Map<String, Asking> asking, java.util.Set<String> acked) {
    String mac = f[5].trim().toLowerCase();
    if (mac.isEmpty() || mac.length() > 50) return;
    if ("5".equals(type)) {
      acked.add(mac);
      return;
    }
    if (!"1".equals(type) && !"3".equals(type)) return;
    Asking a = asking.computeIfAbsent(mac, k -> new Asking());
    a.requests++;
    if (a.first == null || at.isBefore(a.first)) a.first = at;
    if (a.last == null || at.isAfter(a.last)) a.last = at;
    String hostname = f[6].trim();
    if (!hostname.isEmpty()) a.hostname = hostname.length() > 255 ? hostname.substring(0, 255) : hostname;
    if (vendorClass != null) a.vendorClass = vendorClass;
    if (f.length > 15 && !blank(f[15])) {
      try {
        a.vlanId = Integer.parseInt(f[15].trim());
      } catch (NumberFormatException ignored) {
        // not a VLAN id
      }
    }
  }

  private static Network network(String[] f) {
    String serverMac = blank(f[9]) ? null : f[9].trim().toLowerCase();
    Long lease = null;
    try {
      if (!blank(f[13])) lease = Long.parseLong(f[13].trim());
    } catch (NumberFormatException ignored) {
      // tshark may print the lease as text; leave it unknown
    }
    Integer vlan = null;
    try {
      if (f.length > 15 && !blank(f[15])) vlan = Integer.parseInt(f[15].trim());
    } catch (NumberFormatException ignored) {
      // not a VLAN id
    }
    Network n =
        new Network(serverMac, cut(f[10], 45), cut(f[11], 45), cut(f[12], 255), lease,
            f.length > 14 ? cut(f[14], 45) : null, vlan);
    return n.serverMac() == null && n.serverId() == null && n.vlanId() == null ? null : n;
  }

  private static boolean blank(String s) {
    return s == null || s.isBlank();
  }

  private static String cut(String s, int max) {
    if (blank(s)) return null;
    String t = s.trim();
    return t.length() > max ? t.substring(0, max) : t;
  }

  /** The first of an aggregated field's values. */
  private static String first(String field) {
    if (field == null) return "";
    int i = field.indexOf(';');
    return (i < 0 ? field : field.substring(0, i)).trim();
  }
}
