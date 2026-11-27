package com.tracepcap.knowledge.contributor;

import com.tracepcap.common.text.Humanize;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.common.net.LocalityRules;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * C2s that no single alert proves, recognised by a chain of weaker signals. Each rule needs every
 * link, and each escalation carries the chain as its reason, so an analyst sees why.
 *
 * <ul>
 *   <li><b>Suspected C2 (reputation + behaviour).</b> A server on a reputation list (Spamhaus DROP,
 *       CINS, known-compromised, as ET's rules carry them) becomes a suspected C2 only when the host
 *       talking to it is <em>already infected</em> (it talked to a confirmed C2 first), the server
 *       is a bare IP (no DNS or TLS name), and the host contacts it in repeated rounds minutes apart,
 *       or seconds after another server that qualifies (rounds: bursts at least a minute apart).
 *       Reputation alone never makes a C2.
 *       <i>2025-01-22 fake software site: 45.125.66.32 (three rounds on TLS port 2917) and
 *       45.125.66.252 (seconds after it in each round), both only on Spamhaus DROP.</i>
 *   <li><b>Probable unsanctioned remote access (install chain).</b> A remote-admin tool known as a
 *       RAT (NetSupport) checking in to a bare IP becomes a C2 for the tool's abuse ("NetSupport RAT") only when, within minutes
 *       before its first check-in, the same host ran PowerShell (or another script engine) against
 *       another outside server that then sent it a large payload. IT pushes these tools too; an
 *       install chain to an unnamed address minutes before is what sets this one apart.
 *       <i>2026-11-10 NetSupport: PowerShell fetched a script from vericheckusgo.com, the same
 *       server sent 6 MB, and 9 seconds later NetSupport began checking in to 93.152.209.36.</i>
 * </ul>
 */
public final class C2Corroboration {

  private C2Corroboration() {}

  /** One escalated server: who talked to it, what it serves (null: unidentified), and why. */
  public record Escalation(String host, String external, String family, String reason, String kind) {}

  static final String SUSPECTED = "suspected-c2";
  static final String INSTALL_CHAIN = "install-chain";

  /** ET's IP-reputation rule groups. */
  private static final Pattern REPUTATION =
      Pattern.compile("^ET (DROP|CINS|COMPROMISED)\\b|Spamhaus|CINS Active Threat", Pattern.CASE_INSENSITIVE);

  /** A script engine fetching from the internet: the usual first step of an install. */
  private static final Pattern SCRIPT_FETCH =
      Pattern.compile(
          "PowerShell|WindowsPowerShell|\\bPS1\\b|mshta|WScript|CScript|Windows Script Host"
              // and the download tools Windows ships, a common first step too (a holdout: curl
              // fetched an EXE from a bare IP before the RAT's C2 traffic)
              + "|\\bcurl\\b|\\bBITS\\b|bitsadmin|certutil|\\bwget\\b",
          Pattern.CASE_INSENSITIVE);

  /**
   * Sessions closer than this are one round. Within a round the fake-site capture's sessions are
   * 13-14 s apart; its rounds are 2.5 to 25 minutes apart.
   */
  static final Duration ROUND_GAP = Duration.ofMinutes(1);

  /** A server contacted this soon after a qualifying one counts as part of its round. */
  static final Duration PAIRED_WITHIN = Duration.ofSeconds(60);

  /** How long before a tool's first check-in an install chain may start. */
  static final Duration INSTALL_WINDOW = Duration.ofMinutes(10);

  /** A payload at least this big, from the server the script fetched from. */
  static final long PAYLOAD_BYTES = 1024L * 1024; // 1 MB, base 1024 as Humanize writes it

  private record Pair(String host, String external) {}

  /**
   * A reputation-listed server the suspected-C2 rule tested and didn't escalate (#1294), with the
   * first requirement it failed.
   */
  public record Rejection(String host, String external, String listedBy, String reason, List<String> conversations) {}

  /** What one pass concluded and what it ruled out. */
  public record Analysis(List<Escalation> escalations, List<Rejection> rejections) {}

  /** The suspected-C2 rule in words, for an answer's steps and a rejection alike. */
  public static final String SUSPECTED_RULE =
      "Reputation alone never makes a C2. A listed server becomes a suspected C2 only when a host"
          + " already talking to a confirmed C2 reaches it by bare IP, in repeated rounds (or seconds"
          + " after another such server).";

  public static List<Escalation> find(
      List<ConversationFacts> convs, Set<String> confirmedC2, LocalityRules local) {
    return analyse(convs, confirmedC2, local).escalations();
  }

  public static Analysis analyse(
      List<ConversationFacts> convs, Set<String> confirmedC2, LocalityRules local) {
    // Every internal host <-> external conversation, by pair, in time order.
    Map<Pair, List<ConversationFacts>> byPair = new LinkedHashMap<>();
    for (ConversationFacts c : convs) {
      String a = c.flow().srcIp(), b = c.flow().dstIp();
      if (a == null || b == null || c.flow().startTime() == null) continue;
      boolean aLocal = local.isLocal(a), bLocal = local.isLocal(b);
      if (aLocal == bLocal) continue;
      Pair p = aLocal ? new Pair(a, b) : new Pair(b, a);
      byPair.computeIfAbsent(p, k -> new ArrayList<>()).add(c);
    }
    byPair.values().forEach(l -> l.sort(Comparator.comparing(c -> c.flow().startTime())));

    // When each host first talked to a confirmed C2: from then on, it is known to be infected.
    Map<String, LocalDateTime> infectedSince = new LinkedHashMap<>();
    byPair.forEach((p, l) -> {
      if (!confirmedC2.contains(p.external())) return;
      LocalDateTime t = l.get(0).flow().startTime();
      infectedSince.merge(p.host(), t, (x, y) -> x.isBefore(y) ? x : y);
    });

    List<Escalation> out = new ArrayList<>();
    List<Rejection> rejected = new ArrayList<>();
    out.addAll(suspectedC2s(byPair, confirmedC2, infectedSince, rejected));
    out.addAll(installChains(byPair, confirmedC2));
    // A server another host's pass escalated isn't a rejection.
    Set<String> escalated = new java.util.HashSet<>();
    out.forEach(e -> escalated.add(e.external()));
    rejected.removeIf(r -> escalated.contains(r.external()));
    return new Analysis(out, onePerServer(rejected));
  }

  /** How close each rejection came: the one that got furthest stands for its server. */
  private static int closeness(Rejection r) {
    String why = r.reason();
    if (why.startsWith("reached in one round")) return 3;
    if (why.startsWith("it was reached by name")) return 2;
    if (why.contains("before it first talked")) return 1;
    return 0;
  }

  /** One rejection per server: the host that came closest, and how many other hosts reached it. */
  static List<Rejection> onePerServer(List<Rejection> rejected) {
    Map<String, List<Rejection>> byServer = new LinkedHashMap<>();
    rejected.forEach(r -> byServer.computeIfAbsent(r.external(), k -> new ArrayList<>()).add(r));
    List<Rejection> out = new ArrayList<>();
    byServer.forEach((ext, rs) -> {
      Rejection best = rs.stream().max(Comparator.comparingInt(C2Corroboration::closeness)).orElseThrow();
      long others = rs.stream().map(Rejection::host).distinct().count() - 1;
      List<String> convs = rs.stream().flatMap(r -> r.conversations().stream()).distinct().limit(20).toList();
      out.add(new Rejection(best.host(), ext, best.listedBy(),
          best.reason() + (others > 0 ? " (" + others + " other host" + (others == 1 ? "" : "s") + " reached it too)" : ""),
          convs));
    });
    return out;
  }

  // ── Suspected C2: reputation + an infected host + scripted rounds ─────────────

  private static List<Escalation> suspectedC2s(
      Map<Pair, List<ConversationFacts>> byPair, Set<String> confirmed,
      Map<String, LocalDateTime> infectedSince, List<Rejection> rejected) {
    // Candidates: reputation-listed, bare IP, first contacted after the host was infected. A listed
    // server that fails one of those is recorded with the first it failed (#1294).
    Map<Pair, String> candidates = new LinkedHashMap<>(); // pair -> the reputation rule
    byPair.forEach((p, l) -> {
      if (confirmed.contains(p.external())) return;
      String rule = l.stream()
          .flatMap(c -> c.findings().suricataAlerts().stream())
          .filter(a -> REPUTATION.matcher(a).find())
          .findFirst().orElse(null);
      if (rule == null) return;
      // Only a server the host reached out to: an inbound scan from a listed address isn't a C2
      // candidate, and recording one per probed host would bury the list.
      boolean reachedOut = l.stream().anyMatch(c -> {
        String init = c.flow().initiatorIp();
        return init != null ? init.equals(p.host()) : p.host().equals(c.flow().srcIp());
      });
      LocalDateTime since = infectedSince.get(p.host());
      String why = since == null
          ? p.host() + " never talked to a confirmed C2, so nothing says it is infected"
          : l.get(0).flow().startTime().isBefore(since)
              ? p.host() + " reached it before it first talked to a confirmed C2"
              : !bareIp(p.external(), l) ? "it was reached by name, not as a bare IP" : null;
      if (why != null) {
        if (reachedOut) rejected.add(new Rejection(p.host(), p.external(), shortRule(rule), why, ids(l)));
        return;
      }
      candidates.put(p, rule);
    });

    Map<Pair, Integer> rounds = new LinkedHashMap<>();
    candidates.keySet().forEach(p -> rounds.put(p, rounds(byPair.get(p))));

    List<Escalation> out = new ArrayList<>();
    candidates.forEach((p, rule) -> {
      int n = rounds.get(p);
      String repeated = null;
      if (n >= 2) {
        repeated = "contacted in " + n + " separate rounds";
      } else {
        // Every session seconds after a server that does repeat: part of the same scripted round.
        for (Pair q : candidates.keySet()) {
          if (q.equals(p) || !q.host().equals(p.host()) || rounds.get(q) < 2) continue;
          if (allWithin(byPair.get(p), byPair.get(q))) {
            repeated = "contacted seconds after " + q.external() + " in each of its rounds";
            break;
          }
        }
      }
      if (repeated == null) {
        rejected.add(new Rejection(p.host(), p.external(), shortRule(rule),
            "reached in one round, and not seconds after a listed server that recurred", ids(byPair.get(p))));
        return;
      }
      out.add(new Escalation(p.host(), p.external(), null,
          "Suspected C2: " + p.external() + " is reputation-listed (" + shortRule(rule) + "), a bare IP, "
              + repeated + " by " + p.host() + ", which was already talking to a confirmed C2.",
          SUSPECTED));
    });
    return out;
  }

  private static List<String> ids(List<ConversationFacts> l) {
    return l.stream().map(c -> c.id().toString()).toList();
  }

  /** Bursts of sessions at least {@link #ROUND_GAP} apart. */
  static int rounds(List<ConversationFacts> sessions) {
    int rounds = 0;
    LocalDateTime last = null;
    for (ConversationFacts c : sessions) {
      LocalDateTime t = c.flow().startTime();
      if (last == null || Duration.between(last, t).compareTo(ROUND_GAP) >= 0) rounds++;
      last = t;
    }
    return rounds;
  }

  /** Every session of {@code follower} starts within {@link #PAIRED_WITHIN} after one of {@code leader}'s. */
  private static boolean allWithin(List<ConversationFacts> follower, List<ConversationFacts> leader) {
    for (ConversationFacts f : follower) {
      LocalDateTime t = f.flow().startTime();
      boolean near = leader.stream().anyMatch(l -> {
        Duration d = Duration.between(l.flow().startTime(), t);
        return !d.isNegative() && d.compareTo(PAIRED_WITHIN) <= 0;
      });
      if (!near) return false;
    }
    return true;
  }

  // ── Probable unsanctioned remote access: an install chain, then check-ins ─────

  private static List<Escalation> installChains(
      Map<Pair, List<ConversationFacts>> byPair, Set<String> confirmed) {
    List<Escalation> out = new ArrayList<>();
    byPair.forEach((p, l) -> {
      if (confirmed.contains(p.external()) || !bareIp(p.external(), l)) return;
      String tool = null;
      LocalDateTime firstCheckIn = null;
      for (ConversationFacts c : l) {
        String t = RemoteAccessTools.toolForApp(c.findings().appName());
        for (String a : c.findings().suricataAlerts()) if (t == null) t = RemoteAccessTools.toolIn(a);
        if (t != null && tool == null) {
          tool = t;
          firstCheckIn = c.flow().startTime();
        }
      }
      // Only a tool known as a RAT: a PowerShell, curl or BITS download, a big installer and then
      // TeamViewer or AnyDesk checking in is just as much an IT department installing it.
      if (tool == null || !RemoteAccessTools.isRat(tool)) return;
      final LocalDateTime checkIn = firstCheckIn;

      // On the same host, within the window before: a script engine fetching from another server…
      for (Map.Entry<Pair, List<ConversationFacts>> e : byPair.entrySet()) {
        Pair q = e.getKey();
        if (!q.host().equals(p.host()) || q.external().equals(p.external())) continue;
        ConversationFacts script = e.getValue().stream()
            .filter(c -> inWindow(c.flow().startTime(), checkIn))
            .filter(c -> c.findings().suricataAlerts().stream().anyMatch(a -> SCRIPT_FETCH.matcher(a).find()))
            .findFirst().orElse(null);
        if (script == null) continue;
        // …that then sent the host a large payload, before the first check-in.
        ConversationFacts payload = e.getValue().stream()
            .filter(c -> !c.flow().startTime().isBefore(script.flow().startTime())
                && !c.flow().startTime().isAfter(checkIn))
            .filter(c -> received(c, p.host()) >= PAYLOAD_BYTES)
            .findFirst().orElse(null);
        if (payload == null) continue;

        String family = RemoteAccessTools.abuseName(tool);
        String server = script.tls() != null && script.tls().hostname() != null
            && !script.tls().hostname().equals(q.external())
            ? script.tls().hostname() + " (" + q.external() + ")" : q.external();
        long gap = Duration.between(payload.flow().startTime(), checkIn).getSeconds();
        out.add(new Escalation(p.host(), p.external(), family,
            family + " (probable unsanctioned install): a script engine on " + p.host() + " fetched from "
                + server + ", which then sent " + Humanize.bytes(received(payload, p.host())) + "; " + gap
                + " seconds later " + tool + " began checking in to the bare IP " + p.external() + ".",
            INSTALL_CHAIN));
        return;
      }
    });
    return out;
  }

  private static boolean inWindow(LocalDateTime t, LocalDateTime checkIn) {
    return !t.isAfter(checkIn) && Duration.between(t, checkIn).compareTo(INSTALL_WINDOW) <= 0;
  }

  /** Bytes the host received in this flow; the total when direction wasn't recorded. */
  private static long received(ConversationFacts c, String host) {
    Long sent = c.flow().bytesSentBy(host);
    return sent == null ? c.flow().totalBytes() : c.flow().totalBytes() - sent;
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  /** No DNS or TLS name ever seen for the server: an address nobody named. */
  private static boolean bareIp(String ip, List<ConversationFacts> sessions) {
    return sessions.stream().allMatch(c -> {
      String h = c.tls() == null ? null : c.tls().hostname();
      return h == null || h.isBlank() || h.equals(ip);
    });
  }

  /** "ET DROP Spamhaus DROP Listed Traffic Inbound group 7 (sid:…)" -> "Spamhaus DROP". */
  private static String shortRule(String rule) {
    if (rule.contains("Spamhaus")) return "Spamhaus DROP";
    if (rule.toUpperCase().contains("CINS")) return "CINS";
    if (rule.toUpperCase().contains("COMPROMISED")) return "known compromised";
    return rule;
  }
}
