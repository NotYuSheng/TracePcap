package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.common.net.ServicePorts;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The one answer to "which client→server flows are periodic enough to look like a beacon" (#823).
 *
 * <p>Two places used to compute this independently — the beacon {@link BeaconDetector} and the
 * Story aggregates panel — with the same flaws, so fixing one left the other feeding the same false
 * lead to the narrative. They now both call here.
 *
 * <p>Periodicity alone is a weak signal; it only means something together with <em>where</em> the
 * traffic goes. This therefore:
 *
 * <ul>
 *   <li>treats a periodic flow to an <b>external</b> host as a candidate;
 *   <li>treats one to an <b>internal</b> host as ordinary unless it is on a non-service port and
 *       nDPI could not name it (a workstation's NetBIOS keepalive to its domain controller is exactly
 *       30 s, CV 0.000, and entirely normal);
 *   <li>skips inbound and external↔external flows — this is about a <em>host beaconing out</em>;
 *   <li>reports one candidate per client→server:port. The parser stores a single TCP session as
 *       several conversation rows (TCP, NBSS, SMB, LANMAN…) at the same instant, which used to yield
 *       one candidate each and fill the whole result cap;
 *   <li>orders external candidates first, so exact-interval internal traffic cannot crowd a real
 *       beacon out of a capped result.
 * </ul>
 */
public final class BeaconAnalysis {

  private BeaconAnalysis() {}

  private static final int MIN_FLOWS = 3;
  private static final double MIN_MEAN_INTERVAL_MS = 1000;
  private static final double MAX_CV = 0.3;

  /** Where the periodic traffic goes, relative to the client. Declared in reporting priority order. */
  public enum Scope {
    OUTBOUND,
    INTERNAL
  }

  /**
   * One periodic client→server:port flow, with every protocol view of it folded in.
   *
   * @param appName nDPI's name for the application if any view of the flow was identified, else null
   * @param protocols every protocol view seen (e.g. TCP, NBSS, SMB), in first-seen order
   */
  public record Candidate(
      String client,
      String server,
      Integer serverPort,
      Scope scope,
      Set<String> protocols,
      String appName,
      int flows,
      double meanMs,
      double cv) {}

  /** One conversation, oriented client → server. */
  private record Oriented(
      String client, String server, Integer port, String proto, LocalDateTime start, String app) {}

  private record Pair(String client, String server, Integer port) {}

  private record View(Pair pair, String proto) {}

  /** Periodic client→server flows in reporting order: external before internal, then most regular. */
  public static List<Candidate> analyse(List<ConversationFacts> conversations) {
    Map<View, List<Oriented>> views = new LinkedHashMap<>();
    for (ConversationFacts c : conversations) {
      Oriented o = orient(c);
      if (o == null) continue;
      views
          .computeIfAbsent(new View(new Pair(o.client(), o.server(), o.port()), o.proto()), k -> new ArrayList<>())
          .add(o);
    }

    Map<Pair, Candidate> best = new LinkedHashMap<>();
    Map<Pair, Set<String>> protocolsByPair = new LinkedHashMap<>();
    Map<Pair, String> appByPair = new LinkedHashMap<>();
    for (Map.Entry<View, List<Oriented>> e : views.entrySet()) {
      Candidate c = candidate(e.getKey(), e.getValue());
      if (c == null) continue;
      Pair pair = e.getKey().pair();
      protocolsByPair.computeIfAbsent(pair, k -> new LinkedHashSet<>()).addAll(c.protocols());
      if (c.appName() != null) appByPair.putIfAbsent(pair, c.appName());
      best.merge(pair, c, BeaconAnalysis::tighter);
    }

    return best.entrySet().stream()
        .map(
            e -> {
              Candidate c = e.getValue();
              return new Candidate(
                  c.client(), c.server(), c.serverPort(), c.scope(),
                  protocolsByPair.get(e.getKey()), appByPair.get(e.getKey()),
                  c.flows(), c.meanMs(), c.cv());
            })
        .sorted(Comparator.comparing(Candidate::scope).thenComparingDouble(Candidate::cv))
        .collect(Collectors.toList());
  }

  /**
   * Orients a conversation client → server. A conversation's {@code srcIp} is not "the client"
   * (keys are normalised so A→B and B→A share a row), so the initiator is used where known. Where it
   * is not (UDP/ICMP, or a capture that began mid-flow) and exactly one endpoint is internal, the
   * internal host is taken as the client — it is the one that would be beaconing out.
   */
  private static Oriented orient(ConversationFacts c) {
    FlowIdentity f = c.flow();
    if (f.srcIp() == null || f.dstIp() == null || f.startTime() == null) return null;

    boolean serverIsDst;
    String initiator = f.initiatorIp();
    if (initiator != null && initiator.equals(f.srcIp())) {
      serverIsDst = true;
    } else if (initiator != null && initiator.equals(f.dstIp())) {
      serverIsDst = false;
    } else {
      boolean srcLocal = IpLocality.isLocal(f.srcIp());
      boolean dstLocal = IpLocality.isLocal(f.dstIp());
      serverIsDst = srcLocal == dstLocal || srcLocal; // exactly one internal endpoint → it is the client
    }

    String app = c.findings() == null ? null : c.findings().appName();
    boolean identified = app != null && !app.isBlank() && !"unknown".equalsIgnoreCase(app.trim());
    return new Oriented(
        serverIsDst ? f.srcIp() : f.dstIp(),
        serverIsDst ? f.dstIp() : f.srcIp(),
        serverIsDst ? f.dstPort() : f.srcPort(),
        f.protocol() == null ? "" : f.protocol(),
        f.startTime(),
        identified ? app.trim() : null);
  }

  /** The periodicity of one protocol view, or null if it is not periodic or not worth reporting. */
  private static Candidate candidate(View view, List<Oriented> flows) {
    if (flows.size() < MIN_FLOWS) return null;

    List<LocalDateTime> times = flows.stream().map(Oriented::start).sorted().collect(Collectors.toList());
    List<Long> intervals = new ArrayList<>();
    for (int i = 1; i < times.size(); i++) {
      long ms = Duration.between(times.get(i - 1), times.get(i)).toMillis();
      if (ms >= 0) intervals.add(ms);
    }
    if (intervals.isEmpty()) return null;

    double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
    if (mean < MIN_MEAN_INTERVAL_MS) return null;
    double variance = intervals.stream().mapToDouble(v -> Math.pow(v - mean, 2)).average().orElse(0);
    double cv = Math.sqrt(variance) / mean;
    if (cv >= MAX_CV) return null;

    Pair pair = view.pair();
    if (!IpLocality.isLocal(pair.client())) return null; // inbound, or external↔external

    Scope scope;
    String app = flows.stream().map(Oriented::app).filter(a -> a != null).findFirst().orElse(null);
    if (!IpLocality.isLocal(pair.server())) {
      scope = Scope.OUTBOUND;
    } else {
      // Internal → internal: regular traffic to a domain controller / file server / printer is the
      // expected case. Only a flow to a non-service port that nDPI could not name is worth a look.
      if (app != null || ServicePorts.isInfrastructure(pair.port())) return null;
      scope = Scope.INTERNAL;
    }
    return new Candidate(
        pair.client(), pair.server(), pair.port(), scope,
        Set.of(view.proto()), app, flows.size(), mean, cv);
  }

  /** Of two views of the same client→server:port, keep the more regular (then the better-observed). */
  private static Candidate tighter(Candidate a, Candidate b) {
    if (a.cv() != b.cv()) return a.cv() < b.cv() ? a : b;
    return a.flows() >= b.flows() ? a : b;
  }
}
