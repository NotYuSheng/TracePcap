package com.tracepcap.analysis.service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Splits one address's capture into occupancies: stretches of time during which one device held it
 * (#918 item 3). Pure, so analysis and the analyst's split/merge decisions share one rule.
 *
 * <p><b>Automatic boundaries need a different MAC.</b> Each ARP-claimed or DHCP-leased MAC has a
 * window (first to last seen). When the windows follow one another without overlapping, each new
 * MAC starts an occupancy. When any two overlap, two devices answered at once: that's an address
 * conflict (#461), not reuse, and nothing is split automatically. Virtual failover addresses (#947)
 * are never split automatically, and virtual-router MACs are ignored.
 *
 * <p><b>Analyst decisions</b> are applied on top: a merge removes the automatic boundary at its time,
 * a split adds one.
 */
public final class OccupancyBuilder {

  private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  private OccupancyBuilder() {}

  /** One MAC's claim on the address, from ARP or a DHCP lease. */
  public record MacWindow(String mac, LocalDateTime first, LocalDateTime last, String source, String hostname) {}

  /** An analyst's decision; {@code action} is split or merge. */
  public record Decision(LocalDateTime at, String action, String actor, String reason) {}

  /**
   * One occupancy, covering [startsAt, endsAt) (null = capture start/end). {@code startSource} is
   * arp, dhcp or manual, and null for the first.
   */
  public record Occupancy(
      int idx,
      String mac,
      String hostname,
      LocalDateTime startsAt,
      LocalDateTime endsAt,
      String startSource,
      String startEvidence) {}

  /** The result: the occupancies (at least one), the automatic boundaries, and whether MACs overlapped. */
  public record Result(List<Occupancy> occupancies, List<LocalDateTime> automaticBoundaries, boolean overlapping) {}

  /** A MAC's merged window across sources. */
  private static final class Claim {
    final String mac;
    LocalDateTime first;
    LocalDateTime last;
    final TreeSet<String> sources = new TreeSet<>();
    String hostname;

    Claim(String mac, LocalDateTime first, LocalDateTime last) {
      this.mac = mac;
      this.first = first;
      this.last = last;
    }
  }

  private record Boundary(LocalDateTime at, String mac, String source, String evidence) {}

  public static Result build(List<MacWindow> windows, List<Decision> decisions, boolean autoSplitAllowed) {
    List<Claim> claims = merge(windows);

    boolean overlapping = false;
    for (int i = 1; i < claims.size(); i++) {
      if (!claims.get(i).first.isAfter(claims.get(i - 1).last)) overlapping = true;
    }

    List<Boundary> boundaries = new ArrayList<>();
    List<LocalDateTime> automatic = new ArrayList<>();
    if (autoSplitAllowed && !overlapping) {
      for (int i = 1; i < claims.size(); i++) {
        Claim prev = claims.get(i - 1);
        Claim next = claims.get(i);
        String source = next.sources.contains("arp") ? "arp" : "dhcp";
        String evidence =
            (source.equals("arp") ? "ARP: " : "DHCP: ")
                + prev.mac
                + " last seen "
                + TIME.format(prev.last)
                + ", then "
                + next.mac
                + " from "
                + TIME.format(next.first);
        boundaries.add(new Boundary(next.first, next.mac, source, evidence));
        automatic.add(next.first);
      }
    }

    if (decisions != null) {
      for (Decision d : decisions) {
        if ("merge".equals(d.action())) boundaries.removeIf(b -> b.at().equals(d.at()));
      }
      for (Decision d : decisions) {
        if (!"split".equals(d.action()) || d.at() == null) continue;
        if (boundaries.stream().anyMatch(b -> b.at().equals(d.at()))) continue;
        String who = d.actor() == null || d.actor().isBlank() ? "an analyst" : d.actor();
        String why = d.reason() == null || d.reason().isBlank() ? "" : ": " + d.reason();
        boundaries.add(new Boundary(d.at(), macAt(claims, d.at()), "manual", "Split by " + who + why));
      }
    }
    boundaries.sort(Comparator.comparing(Boundary::at));

    List<Occupancy> out = new ArrayList<>();
    String firstMac = claims.isEmpty() ? null : claims.get(0).mac;
    if (!boundaries.isEmpty() && firstMac != null && claims.size() > 1) {
      // With a manual split before any automatic one, the first stretch is whichever MAC held it.
      firstMac = macAt(claims, boundaries.get(0).at().minusNanos(1_000_000));
    }
    String prevMac = firstMac;
    LocalDateTime start = null;
    String startSource = null;
    String startEvidence = null;
    for (int i = 0; i <= boundaries.size(); i++) {
      LocalDateTime end = i < boundaries.size() ? boundaries.get(i).at() : null;
      out.add(
          new Occupancy(out.size(), prevMac, hostnameOf(claims, prevMac), start, end, startSource, startEvidence));
      if (i < boundaries.size()) {
        Boundary b = boundaries.get(i);
        prevMac = b.mac() != null ? b.mac() : prevMac;
        start = b.at();
        startSource = b.source();
        startEvidence = b.evidence();
      }
    }
    return new Result(out, automatic, overlapping);
  }

  private static List<Claim> merge(List<MacWindow> windows) {
    Map<String, Claim> byMac = new LinkedHashMap<>();
    if (windows != null) {
      for (MacWindow w : windows) {
        if (w.mac() == null || w.first() == null || w.last() == null) continue;
        String mac = w.mac().toLowerCase();
        if (FailoverAddressResolverService.isVirtualRouterMac(mac)) continue;
        Claim c = byMac.computeIfAbsent(mac, k -> new Claim(k, w.first(), w.last()));
        if (w.first().isBefore(c.first)) c.first = w.first();
        if (w.last().isAfter(c.last)) c.last = w.last();
        if (w.source() != null) c.sources.add(w.source());
        if (w.hostname() != null && !w.hostname().isBlank()) c.hostname = w.hostname();
      }
    }
    List<Claim> claims = new ArrayList<>(byMac.values());
    claims.sort(Comparator.comparing((Claim c) -> c.first).thenComparing(c -> c.mac));
    return claims;
  }

  /** The MAC holding the address at {@code t}: the claim whose window contains it, else the latest begun. */
  private static String macAt(List<Claim> claims, LocalDateTime t) {
    String latestBegun = null;
    for (Claim c : claims) {
      if (!c.first.isAfter(t) && !c.last.isBefore(t)) return c.mac;
      if (!c.first.isAfter(t)) latestBegun = c.mac;
    }
    return latestBegun;
  }

  private static String hostnameOf(List<Claim> claims, String mac) {
    if (mac == null) return null;
    for (Claim c : claims) if (c.mac.equals(mac)) return c.hostname;
    return null;
  }
}
