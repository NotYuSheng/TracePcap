package com.tracepcap.report;

import com.tracepcap.analysis.dto.occupancy.HostOccupancyResponse;
import com.tracepcap.analysis.dto.segments.NetworkSegmentsResponse;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.common.net.IpLocality;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The report's "Needs a look": what was flagged, worded as sentences with the devices named, most
 * serious first. A flag on a handful of conversations is told one conversation at a time; a flag on
 * a large share of the capture is one line, since it is more often a trait of the capture's devices
 * than something to act on.
 */
final class ReportFindings {

  enum Level {
    HIGH,
    MEDIUM,
    LOW
  }

  /** One thing to look at. {@code source} says which detector raised it. */
  record Finding(Level level, String title, String body, String source) {}

  /** Up to this many conversations under one flag are told one by one. */
  static final int TOLD_ONE_BY_ONE = 3;
  /** A flag on more than this many conversations is told as one line. */
  static final int SPECIFIC_MAX = 5;
  /** A flag on at least this share of all conversations is "on many": the lowest level. */
  static final double MANY_SHARE = 0.2;

  private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

  /** What some nDPI risks mean, in a sentence. Others are named as they are. */
  private static final Map<String, String> MEANING =
      Map.of(
          "unsafe_protocol", "It sends what it carries, logins included, without encryption.",
          "clear_text_credentials", "A username or password crossed the network in clear text.",
          "known_proto_on_non_std_port", "A known protocol on a port it doesn't normally use.",
          "self_signed_cert", "The server presented a self-signed certificate.",
          "obsolete_tls_version", "It used a TLS version that is no longer considered safe.",
          "binary_application_transfer", "A program file was transferred.");

  private ReportFindings() {}

  private enum Source {
    SURICATA("Suricata", 0),
    RULE("Your rule", 1),
    NDPI("nDPI", 2);

    final String label;
    final int rank;

    Source(String label, int rank) {
      this.label = label;
      this.rank = rank;
    }
  }

  private record Flag(Source source, String name) {}

  static List<Finding> build(
      List<ConversationFacts> flagged,
      long totalConversations,
      ReportNames names,
      List<HostOccupancyResponse.ReusedAddress> sharedAddresses,
      NetworkSegmentsResponse networks,
      boolean appendixIncluded) {
    List<Finding> out = new ArrayList<>();

    // Each flag and the conversations carrying it.
    Map<Flag, List<ConversationFacts>> byFlag = new LinkedHashMap<>();
    for (ConversationFacts c : flagged) {
      for (Flag f : flagsOf(c)) byFlag.computeIfAbsent(f, k -> new ArrayList<>()).add(c);
    }
    List<Map.Entry<Flag, List<ConversationFacts>>> flags = new ArrayList<>(byFlag.entrySet());
    flags.sort(
        Comparator.comparingInt((Map.Entry<Flag, List<ConversationFacts>> e) -> e.getKey().source().rank)
            .thenComparingInt(e -> e.getValue().size()));

    for (var e : flags) {
      Flag flag = e.getKey();
      List<ConversationFacts> convs = e.getValue();
      boolean many = totalConversations > 0 && convs.size() >= MANY_SHARE * totalConversations;
      if (convs.size() <= TOLD_ONE_BY_ONE && !many) {
        for (ConversationFacts c : convs) out.add(one(flag, c, names, level(flag, convs.size(), many)));
      } else {
        out.add(summary(flag, convs, totalConversations, names, level(flag, convs.size(), many), many, appendixIncluded));
      }
    }

    // Addresses that changed hands.
    for (var r : sharedAddresses) {
      if (r.occupancies().size() < 2 || !IpLocality.isHostAddress(r.ip())) continue;
      List<String> parts = new ArrayList<>();
      var holders = r.occupancies();
      for (int i = 0; i < holders.size(); i++) {
        var h = holders.get(i);
        String who = (h.getHostname() != null ? h.getHostname() + " (" + h.getMac() + ")" : h.getMac());
        if (h.getNetwork() != null) {
          parts.add(who + " on " + h.getNetwork());
        } else if (i == 0) {
          parts.add(who + (h.getEndsAt() != null ? " until " + time(h.getEndsAt()) : ""));
        } else {
          parts.add((i == holders.size() - 1 ? "then " : "") + who
              + (h.getStartsAt() != null ? " from " + time(h.getStartsAt()) : ""));
        }
      }
      String evidence = holders.stream().map(HostOccupancyResponse.Occupancy::getStartSource)
          .filter(s -> s != null && !s.isBlank()).map(s -> s.equalsIgnoreCase("arp") ? "ARP" : s.equalsIgnoreCase("dhcp") ? "DHCP" : s)
          .distinct().collect(Collectors.joining(" and "));
      boolean sameRange = holders.stream().anyMatch(h -> h.getNetwork() != null);
      out.add(new Finding(
          Level.MEDIUM,
          (sameRange ? "One address on " : "One address, ") + holders.size()
              + (sameRange ? " networks: " : " devices: ") + r.ip(),
          String.join(", ", parts) + "." + (evidence.isEmpty() ? "" : " From " + evidence + "."),
          "Address history"));
    }

    // Devices that asked for an address and got none.
    List<String> asked = new ArrayList<>();
    if (networks != null) {
      for (var s : networks.segments())
        for (var u : s.unanswered()) asked.add(unanswered(u, s.label()));
      for (var u : networks.unanswered()) asked.add(unanswered(u, u.vlanId() != null ? "VLAN " + u.vlanId() : null));
    }
    if (!asked.isEmpty()) {
      String title = asked.size() == 1
          ? "A device asked for an address and got none"
          : asked.size() + " devices asked for an address and got none";
      String body = String.join("; ", asked.subList(0, Math.min(5, asked.size())))
          + (asked.size() > 5 ? "; and " + (asked.size() - 5) + " more" : "")
          + ". No DHCP server answered.";
      out.add(new Finding(Level.MEDIUM, title, body, "DHCP"));
    }

    out.sort(Comparator.comparing(Finding::level));
    return out;
  }

  private static Level level(Flag flag, int count, boolean many) {
    if (flag.source() != Source.NDPI) return Level.HIGH;
    if (many) return Level.LOW;
    return count <= SPECIFIC_MAX ? Level.HIGH : Level.MEDIUM;
  }

  private static Finding one(Flag flag, ConversationFacts c, ReportNames names, Level level) {
    var f = c.flow();
    LocalDateTime at = f.startTime();
    String from = initiator(c);
    String to = from.equals(f.srcIp()) ? f.dstIp() : f.srcIp();
    Integer port = from.equals(f.srcIp()) ? f.dstPort() : f.srcPort();
    String app = app(c);
    String title = app + " to " + nameOr(names, to, at) + " from " + nameOr(names, from, at);
    StringBuilder body = new StringBuilder();
    body.append(names.describe(from, at)).append(" opened ").append(app).append(" to ")
        .append(names.describe(to, at));
    if (port != null) body.append(" on port ").append(port);
    if (at != null) body.append(" at ").append(time(at));
    body.append('.');
    String meaning = flag.source() == Source.NDPI ? MEANING.get(flag.name()) : null;
    if (meaning != null) body.append(' ').append(meaning);
    return new Finding(level, title, body.toString(), flag.source().label + ": " + flag.name());
  }

  private static Finding summary(
      Flag flag, List<ConversationFacts> convs, long total, ReportNames names, Level level,
      boolean many, boolean appendixIncluded) {
    Set<String> from = new LinkedHashSet<>();
    Map<String, Integer> apps = new LinkedHashMap<>();
    for (ConversationFacts c : convs) {
      from.add(initiator(c));
      apps.merge(app(c), 1, Integer::sum);
    }
    String mix = apps.entrySet().stream()
        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
        .limit(5)
        .map(e -> e.getKey() + " " + e.getValue())
        .collect(Collectors.joining(", "));
    if (apps.size() > 5) mix += ", and " + (apps.size() - 5) + " more";
    String who = from.size() == 1
        ? "from " + names.describe(from.iterator().next(), null)
        : "from " + from.size() + " addresses";
    StringBuilder body = new StringBuilder()
        .append(flag.source().label).append(" flagged ").append(convs.size()).append(" of ")
        .append(total).append(" conversations ").append(who).append(" (").append(mix).append(").");
    if (many) {
      body.append(" A flag on this many conversations is more often a trait of the capture's devices"
          + " than an attack; check a few before acting.");
    } else if (flag.source() == Source.NDPI && MEANING.containsKey(flag.name())) {
      body.append(' ').append(MEANING.get(flag.name()));
    }
    if (appendixIncluded) body.append(" Every one is listed in the appendix.");
    String title = many
        ? "Flagged on many conversations: " + flag.name()
        : flag.name() + " on " + convs.size() + " conversations";
    return new Finding(level, title, body.toString(), flag.source().label + ": " + flag.name());
  }

  /** The flags on a conversation, each source's names in order. */
  static List<Flag> flagsOf(ConversationFacts c) {
    var f = c.findings();
    List<Flag> out = new ArrayList<>();
    if (f == null) return out;
    if (f.suricataAlerts() != null) f.suricataAlerts().forEach(n -> out.add(new Flag(Source.SURICATA, n)));
    if (f.customSignatures() != null) f.customSignatures().forEach(n -> out.add(new Flag(Source.RULE, n)));
    if (f.flowRisks() != null) f.flowRisks().forEach(n -> out.add(new Flag(Source.NDPI, n)));
    return out;
  }

  /** Every flag on a conversation, for a table cell. */
  static String flagText(ConversationFacts c) {
    return flagsOf(c).stream().map(f -> f.source() == Source.NDPI ? f.name() : f.source().label + ": " + f.name())
        .collect(Collectors.joining(", "));
  }

  /** The flags on a conversation as "source: name" keys, for grouping in the appendix. */
  static List<String> flagKeys(ConversationFacts c) {
    return flagsOf(c).stream().map(f -> f.source().label + ": " + f.name()).toList();
  }

  static String initiator(ConversationFacts c) {
    var f = c.flow();
    return f.initiatorIp() != null ? f.initiatorIp() : f.srcIp();
  }

  static String app(ConversationFacts c) {
    var f = c.findings();
    if (f != null && f.appName() != null && !f.appName().isBlank()) return f.appName();
    if (f != null && f.tsharkProtocol() != null) return f.tsharkProtocol();
    return c.flow().protocol() != null ? c.flow().protocol() : "Traffic";
  }

  private static String nameOr(ReportNames names, String ip, LocalDateTime at) {
    String n = names.name(ip, at);
    return n == null || "Gateway".equals(n) ? (n == null ? ip : "the gateway " + ip) : n;
  }

  private static String unanswered(NetworkSegmentsResponse.UnansweredClient u, String where) {
    String who = (u.hostname() != null ? u.hostname() + " (" + u.mac() + ")" : u.mac());
    return who + " sent " + u.requests() + " DHCP request" + (u.requests() == 1 ? "" : "s")
        + (where != null ? " on " + where : "");
  }

  static String time(LocalDateTime t) {
    return t == null ? "" : t.format(TIME);
  }
}
