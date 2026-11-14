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

    List<Move> out = new ArrayList<>();
    byMac.forEach((mac, stays) -> {
      if (stays.size() < 2 || MacKind.of(mac) == MacKind.VIRTUAL_ROUTER) return;
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

  private static Stay stay(
      Map<String, Map<String, Stay>> byMac, String mac, String ip, LocalDateTime first, LocalDateTime last) {
    Map<String, Stay> stays = byMac.computeIfAbsent(mac.toLowerCase(Locale.ROOT), k -> new LinkedHashMap<>());
    Stay s = stays.computeIfAbsent(ip, k -> new Stay(ip, first, last));
    s.widen(first, last);
    return s;
  }
}
