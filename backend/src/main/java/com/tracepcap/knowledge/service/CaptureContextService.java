package com.tracepcap.knowledge.service;

import com.tracepcap.common.text.Humanize;
import com.tracepcap.analysis.spi.AnalysisSummaryLookup;
import com.tracepcap.analysis.spi.CaptureQualityLookup;
import com.tracepcap.analysis.spi.CaptureQualityLookup.QualityNote;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.HostPair;
import com.tracepcap.common.adjudication.HumanOverrideService;
import com.tracepcap.common.adjudication.ManualEvidenceEntity;
import com.tracepcap.common.adjudication.ManualEvidenceRepository;
import com.tracepcap.common.net.LocalityPolicy;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * What a capture can show, before anything it shows is read (docs/architecture/
 * investigation-framework.rst, "Capture context"): where it was taken, how complete it is, and the
 * time it spans. The vantage point frames every other answer: lateral movement can't be seen from an
 * internet uplink, and a host taking connections from the whole internet on every port is a sensor's
 * shape, not a victim's.
 *
 * <p>The vantage point is inferred from the address mix, so it is a vote an analyst can overrule:
 * it answers the {@value #QUESTION} question about entity {@value #ENTITY} through the generic
 * adjudication override and evidence endpoints. Analyst evidence adds its weight to a candidate; an
 * override wins outright.
 */
@Service
@RequiredArgsConstructor
public class CaptureContextService {

  /** The adjudication question key, for overrides and evidence. */
  public static final String QUESTION = "vantage-point";

  /** The one entity the question is about: the capture itself. */
  public static final String ENTITY = "capture";

  /** Below this many conversations, the address mix says too little to place a capture. */
  static final int MIN_CONVERSATIONS = 10;

  /** One host in at least this share of conversations: the capture is that host's traffic. */
  static final double FOCAL_SHARE = 0.8;

  /** Fewer peers than this, with a second host as busy: either end of one pair could be the capture's. */
  static final int TWO_ENDED_PEERS = 3;

  /** A sensor is opened to by at least this many hosts, on at least this many of its ports. */
  static final int SENSOR_OPENERS = 5;

  static final int SENSOR_PORTS = 5;

  /** At least this share of conversations between internal hosts: inside the LAN. */
  static final double LAN_SHARE = 0.2;

  /** At least this share between an internal and an external host: on the uplink. */
  static final double UPLINK_SHARE = 0.6;

  /** Top two candidates within this many points of each other: contested. */
  static final int CONTESTED_MARGIN = 15;

  /** Where a capture was taken. */
  public enum Vantage {
    LAN("lan", "Inside the LAN"),
    UPLINK("uplink", "On the internet uplink"),
    CLIENT("client", "On one host"),
    SERVER("server", "On an exposed server"),
    SENSOR("sensor", "On a honeypot or sensor");

    private final String key;
    private final String label;

    Vantage(String key, String label) {
      this.key = key;
      this.label = label;
    }

    public String key() {
      return key;
    }

    public String label() {
      return label;
    }

    /** The vantage an analyst's label names, or null for a label of their own. */
    static Vantage ofLabel(String label) {
      if (label == null) return null;
      for (Vantage v : values()) {
        if (v.label.equalsIgnoreCase(label.trim()) || v.key.equalsIgnoreCase(label.trim())) return v;
      }
      return null;
    }
  }

  /** One answer the vote considered, and why. */
  public record Candidate(String label, int score, List<String> reasons) {}

  /**
   * Where the capture was taken.
   *
   * @param key the {@link Vantage} key, "other" for an analyst's own label, null when undetermined
   * @param label what to show, e.g. "On a honeypot or sensor"; null when undetermined
   * @param host the one host the capture is centred on, when it is; else null
   * @param basis HUMAN when an analyst overrode it, MACHINE otherwise
   * @param reason why, in a sentence: the inference, the override's rationale, or why it can't tell
   */
  public record VantagePoint(
      String key,
      String label,
      String host,
      String basis,
      int confidence,
      boolean contested,
      List<Candidate> candidates,
      String reason,
      String overriddenBy) {

    public boolean determined() {
      return key != null;
    }

    /** "On a honeypot or sensor (192.168.100.28)". */
    public String described() {
      if (label == null) return null;
      return host == null ? label : label + " (" + host + ")";
    }
  }

  /** How complete the capture is. {@code level}: "complete", "partial" (traffic missing), "notes". */
  public record Completeness(String label, String level, List<QualityNote> notes) {}

  /** The time the capture spans; null times when the summary isn't there yet. */
  public record TimeSpan(LocalDateTime start, LocalDateTime end, Long durationMs, String label) {}

  /**
   * @param internalConversations conversations between two internal hosts: from the uplink, none
   *     means lateral movement can't show; any means some internal traffic is there to look at
   */
  public record CaptureContext(
      VantagePoint vantage, Completeness completeness, TimeSpan timeSpan, long internalConversations) {}

  /**
   * The address mix of a capture.
   *
   * @param internalToInternal conversations between two internal hosts
   * @param internalExternal conversations between an internal and an external host
   * @param focal the host in the most conversations
   * @param focalOpened conversations the focal host opened
   * @param focalAnswered conversations another host opened to the focal host
   * @param focalOpeners distinct hosts that opened a conversation to the focal host
   */
  record Mix(
      long conversations,
      long internalToInternal,
      long internalExternal,
      int internalHosts,
      String focal,
      long focalConversations,
      long focalOpened,
      long focalAnswered,
      int focalOpeners,
      int focalPeers,
      String runnerUp,
      long runnerUpConversations) {

    double share(long n) {
      return conversations == 0 ? 0 : (double) n / conversations;
    }

    /**
     * Two hosts each in most conversations, and the busiest talks to hardly anyone else: a capture of
     * one pair, which could have been taken at either end, so neither is "the" host. A host with
     * other peers is the end the capture sits on, however much of its traffic goes to one of them (a
     * compromised sensor flooding one target).
     */
    boolean twoEnded() {
      return share(focalConversations) >= FOCAL_SHARE && share(runnerUpConversations) >= FOCAL_SHARE
          && focalPeers < TWO_ENDED_PEERS;
    }

    /** One host dominates, and only one: the capture is that host's traffic. */
    boolean hostCentred() {
      return share(focalConversations) >= FOCAL_SHARE && !twoEnded();
    }
  }

  private final ConversationLookup conversations;
  private final AnalysisSummaryLookup summaries;
  private final CaptureQualityLookup quality;
  private final LocalityPolicy locality;
  private final HumanOverrideService overrides;
  private final ManualEvidenceRepository evidence;

  public CaptureContext forFile(UUID fileId) {
    Mix mix = mix(conversations.hostPairs(fileId), locality.currentRules()::isLocal);
    long answeredPorts = mix.hostCentred() ? conversations.distinctAnsweredPorts(fileId, mix.focal()) : 0;
    VantagePoint inferred = decide(infer(mix, answeredPorts), mix,
        evidence.findByQuestionAndFileId(QUESTION, fileId).stream()
            .filter(e -> ENTITY.equals(e.getEntityKey())).toList());
    VantagePoint vantage = overrides.find(QUESTION, fileId, ENTITY)
        .map(o -> overridden(inferred, o.getLabel(), o.getRationale(), o.getActor()))
        .orElse(inferred);
    return new CaptureContext(vantage, completeness(quality.qualityNotes(fileId)), timeSpan(fileId),
        mix.internalToInternal());
  }

  // ── The address mix ───────────────────────────────────────────────────────────────────────

  static Mix mix(List<HostPair> pairs, Predicate<String> isLocal) {
    long total = 0, ii = 0, ie = 0;
    Set<String> internal = new HashSet<>();
    Map<String, Long> perHost = new HashMap<>();
    for (HostPair p : pairs) {
      total += p.conversations();
      boolean a = isLocal.test(p.a()), b = isLocal.test(p.b());
      if (a) internal.add(p.a());
      if (b) internal.add(p.b());
      if (a && b) ii += p.conversations();
      else if (a || b) ie += p.conversations();
      perHost.merge(p.a(), p.conversations(), Long::sum);
      if (!p.b().equals(p.a())) perHost.merge(p.b(), p.conversations(), Long::sum);
    }
    // Ties go to the lexically first host, so the same capture always names the same one.
    List<String> busiest = perHost.entrySet().stream()
        .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
            .thenComparing(Map.Entry.comparingByKey()))
        .limit(2).map(Map.Entry::getKey).toList();
    String focal = busiest.isEmpty() ? null : busiest.get(0);
    String runnerUp = busiest.size() < 2 ? null : busiest.get(1);
    long opened = 0, answered = 0;
    Set<String> openers = new HashSet<>();
    Set<String> peers = new HashSet<>();
    for (HostPair p : pairs) {
      if (focal == null) break;
      if (focal.equals(p.a())) {
        peers.add(p.b());
        opened += p.openedByA();
        answered += p.openedByB();
        if (p.openedByB() > 0) openers.add(p.b());
      } else if (focal.equals(p.b())) {
        peers.add(p.a());
        opened += p.openedByB();
        answered += p.openedByA();
        if (p.openedByA() > 0) openers.add(p.a());
      }
    }
    return new Mix(total, ii, ie, internal.size(), focal,
        focal == null ? 0 : perHost.get(focal), opened, answered, openers.size(),
        peers.size(), runnerUp, runnerUp == null ? 0 : perHost.get(runnerUp));
  }

  // ── The vote ──────────────────────────────────────────────────────────────────────────────

  /**
   * Each vantage the mix supports, scored 0–100 with its reasons, best first. Empty when the mix
   * can't place the capture; {@link #undetermined} says why.
   */
  static List<Candidate> infer(Mix m, long answeredPorts) {
    if (m.conversations() < MIN_CONVERSATIONS) return List.of();
    List<Candidate> out = new ArrayList<>();
    if (m.twoEnded()) return List.of();
    double focalShare = m.share(m.focalConversations());
    if (focalShare >= FOCAL_SHARE) {
      String centred = m.focal() + " is in " + pct(focalShare) + " of conversations";
      long known = m.focalOpened() + m.focalAnswered();
      if (known == 0) {
        out.add(new Candidate(Vantage.CLIENT.label(), 40,
            List.of(centred, "which side opened them isn't known (no TCP handshakes)")));
      } else {
        String opened = m.focalAnswered() == 0
            ? "it opened " + Humanize.plural(m.focalOpened(), "conversation") + "; no host opened one to it"
            : Humanize.plural(m.focalOpeners(), "host") + " opened " + Humanize.plural(m.focalAnswered(), "conversation")
                + " to it on " + Humanize.plural(answeredPorts, "port") + "; it opened " + m.focalOpened();
        boolean probed = m.focalOpeners() >= SENSOR_OPENERS && answeredPorts >= SENSOR_PORTS;
        String sensorShape = "many hosts probing many ports is a sensor's shape; a server answers a few";
        if ((double) m.focalAnswered() / known >= 0.5) {
          if (probed) {
            out.add(new Candidate(Vantage.SENSOR.label(), 75, List.of(centred, opened, sensorShape)));
            out.add(new Candidate(Vantage.SERVER.label(), 35, List.of(centred, opened)));
          } else {
            out.add(new Candidate(Vantage.SERVER.label(), 65, List.of(centred, opened)));
            out.add(new Candidate(Vantage.SENSOR.label(), 25, List.of(centred, opened)));
          }
        } else {
          out.add(new Candidate(Vantage.CLIENT.label(), 70, List.of(centred, opened)));
          // A compromised honeypot turns to attacking out, and its own traffic then outweighs the
          // probes it still takes: keep the sensor in view rather than lose it to the count.
          if (probed) {
            out.add(new Candidate(Vantage.SENSOR.label(), 50, List.of(centred, opened, sensorShape)));
          }
        }
      }
      return out;
    }
    if (m.internalHosts() < 2) return List.of();
    double ii = (double) m.internalToInternal() / m.conversations();
    double ie = (double) m.internalExternal() / m.conversations();
    String hosts = Humanize.plural(m.internalHosts(), "internal host");
    if (ii >= LAN_SHARE) {
      out.add(new Candidate(Vantage.LAN.label(), 70,
          List.of(hosts, pct(ii) + " of conversations are between internal hosts")));
      if (ie >= LAN_SHARE) {
        out.add(new Candidate(Vantage.UPLINK.label(), 30,
            List.of(pct(ie) + " of conversations reach outside")));
      }
    } else if (ie >= UPLINK_SHARE) {
      out.add(new Candidate(Vantage.UPLINK.label(), 65, List.of(hosts,
          pct(ie) + " of conversations reach outside, only " + pct(ii) + " stay inside")));
      out.add(new Candidate(Vantage.LAN.label(), 20, List.of(hosts)));
    }
    return out;
  }

  /** Why the mix can't place a capture. */
  static String undetermined(Mix m) {
    if (m.conversations() < MIN_CONVERSATIONS) {
      return "only " + Humanize.plural(m.conversations(), "conversation") + ", too few to tell where it was taken";
    }
    if (m.twoEnded()) {
      return "most of it is between two hosts, " + m.focal() + " and " + m.runnerUp()
          + ", and it could have been taken at either end";
    }
    if (m.internalHosts() < 2) {
      return "no one host dominates and under 2 hosts are internal: if these addresses are yours,"
          + " add them as private ranges";
    }
    return "the address mix doesn't settle it: neither mostly internal nor mostly outbound";
  }

  /** The machine's verdict, after analyst evidence adds its weight to the candidates. */
  static VantagePoint decide(List<Candidate> machine, Mix m, List<ManualEvidenceEntity> analyst) {
    Map<String, Candidate> byLabel = new LinkedHashMap<>();
    machine.forEach(c -> byLabel.put(canonical(c.label()), c));
    for (ManualEvidenceEntity e : analyst) {
      String label = canonical(e.getLabel());
      Candidate was = byLabel.get(label);
      List<String> reasons = new ArrayList<>(was == null ? List.of() : was.reasons());
      reasons.add("analyst evidence: " + e.getReason());
      byLabel.put(label, new Candidate(label, Math.min(100, (was == null ? 0 : was.score())
          + e.getWeight()), List.copyOf(reasons)));
    }
    List<Candidate> ranked = byLabel.values().stream()
        .sorted(Comparator.comparingInt(Candidate::score).reversed()).toList();
    if (ranked.isEmpty()) {
      return new VantagePoint(null, null, null, "MACHINE", 0, false, List.of(), undetermined(m), null);
    }
    Candidate top = ranked.get(0);
    boolean contested = ranked.size() > 1 && top.score() - ranked.get(1).score() < CONTESTED_MARGIN;
    Vantage v = Vantage.ofLabel(top.label());
    boolean centred = (v == Vantage.CLIENT || v == Vantage.SERVER || v == Vantage.SENSOR)
        && m.hostCentred();
    // Where the address mix settled nothing, the answer is the analyst's evidence alone: theirs, not
    // an inference.
    String basis = machine.isEmpty() ? "HUMAN" : "MACHINE";
    String reason = machine.isEmpty()
        ? undetermined(m) + "; set from " + String.join("; ", top.reasons())
        : String.join("; ", top.reasons());
    return new VantagePoint(v == null ? "other" : v.key(), top.label(), centred ? m.focal() : null,
        basis, top.score(), contested, ranked, reason, null);
  }

  /** An analyst's answer, which wins outright; the machine's candidates stay for reference. */
  static VantagePoint overridden(VantagePoint inferred, String label, String rationale, String actor) {
    Vantage v = Vantage.ofLabel(label);
    String shown = v == null ? label.trim() : v.label();
    // Keep the host the capture centres on when the analyst picked a host-centred vantage too.
    boolean centred = v == Vantage.CLIENT || v == Vantage.SERVER || v == Vantage.SENSOR;
    String reason = rationale == null || rationale.isBlank() ? "set by an analyst" : rationale.trim();
    return new VantagePoint(v == null ? "other" : v.key(), shown, centred ? inferred.host() : null,
        "HUMAN", 100, false, inferred.candidates(), reason, actor);
  }

  /** A known vantage's own label whatever its spelling, so evidence and inference share a row. */
  private static String canonical(String label) {
    Vantage v = Vantage.ofLabel(label);
    return v == null ? label.trim() : v.label();
  }

  // ── Completeness and time span ────────────────────────────────────────────────────────────

  /** Short names for the quality notes, for a one-line verdict. */
  private static final Map<String, String> NOTE_SHORT = Map.of(
      "suricata-unread", "the IDS couldn't read all of it",
      "gaps", "gaps in TCP streams",
      "memcap", "the IDS ran out of memory",
      "midstream", "connections already open when it began",
      "invalid", "undecodable packets",
      "depth", "long sessions only partly inspected");

  static Completeness completeness(List<QualityNote> notes) {
    if (notes.isEmpty()) {
      return new Completeness("Complete: no gaps, no connections cut off at the start", "complete", notes);
    }
    // Long sessions past the IDS's inspection depth say how far Suricata read, not what the capture
    // holds: listed with the notes, but they don't qualify the verdict.
    List<QualityNote> capture = notes.stream().filter(n -> !"depth".equals(n.kind())).toList();
    if (capture.isEmpty()) {
      return new Completeness("Complete: no gaps, no connections cut off at the start", "complete", notes);
    }
    boolean missing = capture.stream().anyMatch(n -> "warning".equals(n.level()));
    String what = String.join(", ",
        capture.stream().map(n -> NOTE_SHORT.getOrDefault(n.kind(), n.kind())).toList());
    return new Completeness((missing ? "Partial: " : "Complete, with notes: ") + what,
        missing ? "partial" : "notes", notes);
  }

  private static final DateTimeFormatter WHEN = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.ROOT);

  private TimeSpan timeSpan(UUID fileId) {
    return summaries.summaryFor(fileId)
        .map(s -> timeSpan(s.startTime(), s.endTime(), s.durationMs()))
        .orElse(new TimeSpan(null, null, null, null));
  }

  static TimeSpan timeSpan(LocalDateTime start, LocalDateTime end, Long durationMs) {
    if (start == null || end == null || durationMs == null) return new TimeSpan(start, end, durationMs, null);
    String label = Humanize.span(durationMs) + ", " + WHEN.format(start) + " to "
        + (start.toLocalDate().equals(end.toLocalDate()) ? end.toLocalTime().toString().substring(0, 5)
            : WHEN.format(end));
    return new TimeSpan(start, end, durationMs, label);
  }

  private static String pct(double share) {
    return Math.round(100 * share) + "%";
  }
}
