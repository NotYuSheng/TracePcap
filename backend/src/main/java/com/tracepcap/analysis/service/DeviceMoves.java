package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.DhcpLeaseEntity;
import com.tracepcap.analysis.entity.IpMacObservationEntity;
import com.tracepcap.common.net.MacKind;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A device that moved to another address within a capture: one MAC that held one address, then a
 * different one (a new DHCP lease, a re-plugged cable). Pure, from the capture's ARP ownership
 * claims and DHCP leases, the same evidence address reuse is read from, read the other way round.
 *
 * <p>Only a hand-over counts: the MAC's time on the first address ended before its time on the
 * next began. A MAC on two addresses at once is multi-homed (or aliased), not moving, and is left
 * out. Virtual router MACs (VRRP/HSRP), which a failover pair shares, are left out too.
 *
 * <p>A device can move any number of times, and come back: A, then B, then A again is two moves.
 * ARP and DHCP evidence is one row per address, first to last seen, so on its own a return looks
 * like being on both at once (A's span covers B's). The MAC's conversations settle it: they say when
 * each address was actually in use. With them, the MAC's use of its addresses is read as a
 * timeline: concurrent use of two addresses is multi-homed; otherwise each change of address is a
 * move, however many there are. Without conversations on two of its addresses, the spans decide,
 * as before.
 */
public final class DeviceMoves {

  private DeviceMoves() {}

  /** One move: {@code mac} left {@code fromIp} (last seen {@code left}) and took {@code toIp} at {@code arrived}. */
  public record Move(
      String mac,
      String fromIp,
      String fromHostname,
      LocalDateTime left,
      String toIp,
      String toHostname,
      LocalDateTime arrived,
      String evidence) {}

  /**
   * A conversation's use of an address by a MAC, from its start to its end. {@code continuous} when
   * its packets fill that span (a transfer, a session); a sparse one (DHCP renewals and ARP on the
   * same ports, minutes apart, are one conversation) only says the address was in use at its two
   * ends.
   */
  public record Sighting(String mac, String ip, LocalDateTime start, LocalDateTime end, boolean continuous) {
    public Sighting(String mac, String ip, LocalDateTime start, LocalDateTime end) {
      this(mac, ip, start, end, true);
    }
  }

  /** Two addresses in use this close together, more than once: on both at once. */
  private static final long CLOSE_SECONDS = 5;

  /** Past this many changes of address per address held, it's flapping between them, not moving. */
  private static final int MAX_RUNS_PER_ADDRESS = 3;

  /** One MAC's time on one address, merged across ARP and DHCP. */
  private static final class Stay {
    final String ip;
    LocalDateTime first;
    LocalDateTime last;
    String hostname;
    boolean dhcp;
    boolean arp;

    Stay(String ip, LocalDateTime first, LocalDateTime last) {
      this.ip = ip;
      this.first = first;
      this.last = last;
    }

    void widen(LocalDateTime f, LocalDateTime l) {
      if (f != null && (first == null || f.isBefore(first))) first = f;
      if (l != null && (last == null || l.isAfter(last))) last = l;
    }
  }

  public static List<Move> of(List<IpMacObservationEntity> arp, List<DhcpLeaseEntity> leases) {
    return of(arp, leases, List.of());
  }

  public static List<Move> of(
      List<IpMacObservationEntity> arp, List<DhcpLeaseEntity> leases, List<Sighting> sightings) {
    Map<String, Map<String, Stay>> byMac = new LinkedHashMap<>();
    for (IpMacObservationEntity o : arp) {
      if (o.getFirstSeen() == null || o.getLastSeen() == null || o.getMac() == null) continue;
      Stay s = stay(byMac, o.getMac(), o.getIp(), o.getFirstSeen(), o.getLastSeen());
      s.arp = true;
    }
    for (DhcpLeaseEntity l : leases) {
      if (l.getMac() == null || l.getFirstSeen() == null) continue;
      Stay s = stay(byMac, l.getMac(), l.getIp(), l.getFirstSeen(), l.getLastSeen());
      s.dhcp = true;
      if (l.getHostname() != null && !l.getHostname().isBlank()) s.hostname = l.getHostname();
    }

    // Conversations, only on addresses ARP or DHCP already tie to the MAC: a routed packet carries
    // the router's MAC with a far-away address, which is not the router moving.
    Map<String, List<Sighting>> seen = new LinkedHashMap<>();
    for (Sighting x : sightings) {
      if (x.mac() == null || x.ip() == null || x.start() == null) continue;
      String mac = x.mac().toLowerCase(Locale.ROOT);
      Map<String, Stay> stays = byMac.get(mac);
      if (stays != null && stays.containsKey(x.ip())) seen.computeIfAbsent(mac, k -> new ArrayList<>()).add(x);
    }

    List<Move> out = new ArrayList<>();
    byMac.forEach((mac, stays) -> {
      if (stays.size() < 2 || MacKind.of(mac) == MacKind.VIRTUAL_ROUTER) return;
      List<Sighting> uses = seen.getOrDefault(mac, List.of());
      if (uses.stream().map(Sighting::ip).distinct().count() >= 2) {
        out.addAll(fromTimeline(mac, stays, uses));
        return;
      }
      List<Stay> ordered = new ArrayList<>(stays.values());
      ordered.sort(Comparator.comparing((Stay s) -> s.first));
      // Any two stays at the same time: multi-homed, not moving.
      for (int i = 1; i < ordered.size(); i++) {
        if (!ordered.get(i).first.isAfter(ordered.get(i - 1).last)) return;
      }
      for (int i = 1; i < ordered.size(); i++) {
        Stay a = ordered.get(i - 1);
        Stay b = ordered.get(i);
        String evidence = b.dhcp ? "DHCP lease" : "ARP";
        out.add(new Move(mac, a.ip, a.hostname, a.last, b.ip, b.hostname, b.first, evidence));
      }
    });
    out.sort(Comparator.comparing(Move::arrived));
    return out;
  }

  /** Reads the MAC's use of its addresses in time order: concurrent use is multi-homed, else each change is a move. */
  private static List<Move> fromTimeline(String mac, Map<String, Stay> stays, List<Sighting> uses) {
    // Every use, in time order: when each conversation started, and the ARP and DHCP sightings.
    List<Sighting> spans = new ArrayList<>();
    List<Sighting> all = new ArrayList<>();
    for (Sighting x : uses) {
      LocalDateTime end = x.end() != null ? x.end() : x.start();
      if (x.continuous() && end.isAfter(x.start())) spans.add(x);
      // Only the start: a conversation's MAC is its first packet's, and one keyed by addresses
      // alone (ARP, DHCP) can carry on with the next device after the address changes hands.
      all.add(new Sighting(mac, x.ip(), x.start(), x.start(), false));
    }
    for (Stay s : stays.values()) {
      all.add(new Sighting(mac, s.ip, s.first, s.first, false));
      if (s.last != null) all.add(new Sighting(mac, s.ip, s.last, s.last, false));
    }
    all.sort(Comparator.comparing(Sighting::start));
    // Multi-homed: a continuous conversation on one address while another is in use...
    for (Sighting span : spans) {
      for (Sighting x : all) {
        if (!x.ip().equals(span.ip()) && x.start().isAfter(span.start()) && x.start().isBefore(span.end())) return List.of();
      }
    }
    // ...or the two addresses seen within seconds of each other, again and again.
    int close = 0;
    for (int i = 1; i < all.size(); i++) {
      Sighting a = all.get(i - 1);
      Sighting b = all.get(i);
      if (!a.ip().equals(b.ip()) && java.time.Duration.between(a.start(), b.start()).getSeconds() < CLOSE_SECONDS) close++;
    }
    if (close >= 2) return List.of();
    // Runs of one address; a change of address between runs is a move.
    List<String> runIp = new ArrayList<>();
    List<LocalDateTime> runFirst = new ArrayList<>();
    List<LocalDateTime> runLast = new ArrayList<>();
    for (Sighting x : all) {
      LocalDateTime end = x.end() != null ? x.end() : x.start();
      int n = runIp.size();
      if (n > 0 && runIp.get(n - 1).equals(x.ip())) {
        if (end.isAfter(runLast.get(n - 1))) runLast.set(n - 1, end);
      } else {
        runIp.add(x.ip());
        runFirst.add(x.start());
        runLast.add(end);
      }
    }
    if (runIp.size() > MAX_RUNS_PER_ADDRESS * stays.size()) return List.of();
    List<Move> moves = new ArrayList<>();
    for (int i = 1; i < runIp.size(); i++) {
      Stay a = stays.get(runIp.get(i - 1));
      Stay b = stays.get(runIp.get(i));
      String evidence = b.dhcp ? "DHCP lease" : b.arp ? "ARP" : "traffic";
      moves.add(new Move(mac, a.ip, a.hostname, runLast.get(i - 1), b.ip, b.hostname, runFirst.get(i), evidence));
    }
    return moves;
  }

  private static Stay stay(
      Map<String, Map<String, Stay>> byMac, String mac, String ip, LocalDateTime first, LocalDateTime last) {
    Map<String, Stay> stays = byMac.computeIfAbsent(mac.toLowerCase(Locale.ROOT), k -> new LinkedHashMap<>());
    Stay s = stays.computeIfAbsent(ip, k -> new Stay(ip, first, last));
    s.widen(first, last);
    return s;
  }
}
