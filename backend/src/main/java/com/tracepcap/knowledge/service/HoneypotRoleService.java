package com.tracepcap.knowledge.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.HostPair;
import com.tracepcap.analysis.spi.ServiceBannerLookup;
import com.tracepcap.analysis.spi.ServiceBannerLookup.Banner;
import com.tracepcap.common.adjudication.HumanOverrideEntity;
import com.tracepcap.common.adjudication.HumanOverrideService;
import com.tracepcap.common.adjudication.ManualEvidenceEntity;
import com.tracepcap.common.adjudication.ManualEvidenceRepository;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Which hosts in a capture are honeypots (docs/architecture/investigation-framework.rst,
 * "Honeypots"). Stock honeypots give themselves away: a default banner, a default certificate, a
 * Windows SMB server on a Linux stack. Each is a <em>signal</em>, matched against the bundled
 * signature file ({@value #SIGNATURES}), or read from how the host behaves.
 *
 * <p><b>One signal is never enough.</b> A real Debian 12 server sends Cowrie's default banner, and a
 * real Synology sends Dionaea's FTP greeting. A host reads as a honeypot when it shows at least two
 * signals, one of them a signature, worth {@value #CONCLUDE} points together: graded INFERRED, as
 * the research it follows does (Srinivasa et al., 2021).
 *
 * <p>The role is a vote an analyst can overrule, per host: it answers the {@value #QUESTION}
 * question about the host's address through the generic adjudication override and evidence
 * endpoints. Evidence adds its weight; an override wins outright.
 */
@Service
@RequiredArgsConstructor
public class HoneypotRoleService {

  public static final String QUESTION = "honeypot";

  public static final String HONEYPOT = "Honeypot";

  public static final String NOT_HONEYPOT = "Not a honeypot";

  static final String SIGNATURES = "honeypot/signatures.json";

  /** Points a host's signals need between them to read as a honeypot. */
  static final int CONCLUDE = 60;

  /** At least this many hosts opened conversations to it: the fan-in a decoy draws. */
  static final int FAN_IN_OPENERS = 5;

  /** It opened at most this share of its own conversations: a decoy starts nothing. */
  static final double FAN_OUT_SHARE = 0.1;

  /** It answered at least this many ports: a real server exposes a few. */
  static final int MANY_PORTS = 5;

  /** Top two candidates within this many points of each other: contested. */
  static final int CONTESTED_MARGIN = 15;

  /**
   * Behaviour is read for at most this many hosts, the strongest signatures first: a capture that
   * scans the internet can meet hundreds of servers still sending an old honeypot's banner.
   */
  static final int MAX_EXAMINED = 50;

  /** How much a signal counts for. */
  public enum Strength {
    STRONG(45),
    MEDIUM(30),
    WEAK(15);

    final int points;

    Strength(int points) {
      this.points = points;
    }
  }

  /** One fingerprint from the signature file. */
  record Signature(String id, String honeypot, String kind, String match, String value,
      Strength strength, String why) {

    boolean matches(String observed) {
      if (observed == null) return false;
      return "contains".equals(match) ? observed.contains(value) : observed.equals(value);
    }
  }

  /**
   * One thing that points at a honeypot.
   *
   * @param source "signature", "behaviour" or "analyst"
   * @param id the signature's id, or the behaviour's name
   * @param honeypot the honeypot a signature names; null for behaviour
   */
  public record Signal(String source, String id, String honeypot, String strength, int points,
      String text) {}

  /** One answer the vote considered, and why. */
  public record Candidate(String label, int score, List<String> reasons) {}

  /**
   * One host's role.
   *
   * @param label {@link #HONEYPOT}, {@link #NOT_HONEYPOT}, an analyst's own; null when its signals
   *     don't settle it
   * @param honeypot which honeypot, when the signatures name one ("Dionaea")
   * @param basis HUMAN when an analyst overrode it or only analyst evidence settled it
   */
  public record HostRole(String host, String label, String honeypot, String basis, int confidence,
      boolean contested, List<Candidate> candidates, List<Signal> signals, String reason,
      String overriddenBy) {

    public boolean isHoneypot() {
      return label != null && !NOT_HONEYPOT.equals(label);
    }

    /** "198.51.100.45 is a Dionaea honeypot". */
    public String described() {
      if (label == null) return null;
      if (NOT_HONEYPOT.equals(label)) return host + " is not a honeypot";
      if (HONEYPOT.equals(label)) {
        return host + " is a " + (honeypot == null ? "" : honeypot + " ") + "honeypot";
      }
      return host + ": " + label;
    }
  }

  /**
   * Every host worth a verdict, honeypots first: a honeypot, a host with two or more signals, or
   * one an analyst spoke to.
   *
   * @param singleSignal hosts with one signature match and nothing else (a stock banner a real
   *     server sends too), counted rather than listed
   * @param serversChecked servers whose banners or certificates were read against the signatures
   */
  public record HoneypotReport(List<HostRole> hosts, int singleSignal, int serversChecked,
      String signaturesVersion) {

    public List<HostRole> honeypots() {
      return hosts.stream().filter(HostRole::isHoneypot).toList();
    }
  }

  private final ServiceBannerLookup banners;
  private final ConversationLookup conversations;
  private final HumanOverrideService overrides;
  private final ManualEvidenceRepository evidence;
  private final ObjectMapper mapper;

  private volatile SignatureFile signatureFile;

  record SignatureFile(String version, List<Signature> signatures) {}

  public HoneypotReport forFile(UUID fileId) {
    SignatureFile file = signatures();
    Map<String, List<String[]>> observed = observations(fileId);
    Map<String, List<Signal>> signals = new LinkedHashMap<>();
    observed.forEach((host, seen) -> {
      List<Signal> s = signatureSignals(seen, file.signatures());
      if (!s.isEmpty()) signals.put(host, s);
    });

    Map<String, List<ManualEvidenceEntity>> analyst = new HashMap<>();
    evidence.findByQuestionAndFileId(QUESTION, fileId)
        .forEach(e -> analyst.computeIfAbsent(e.getEntityKey(), k -> new ArrayList<>()).add(e));
    Set<String> hosts = new TreeSet<>(signals.keySet());
    hosts.addAll(analyst.keySet());
    if (hosts.isEmpty()) return new HoneypotReport(List.of(), 0, observed.size(), file.version());

    // Behaviour reads only the hosts already in question, a signature or an analyst's word, and
    // the strongest of them first.
    List<String> examined = hosts.stream()
        .sorted(Comparator.comparing((String h) -> !analyst.containsKey(h))
            .thenComparing(h -> -signals.getOrDefault(h, List.of()).stream().mapToInt(Signal::points).sum())
            .thenComparing(h -> h))
        .toList();
    List<HostPair> pairs = conversations.hostPairs(fileId);
    List<HostRole> out = new ArrayList<>();
    int single = 0;
    for (int i = 0; i < examined.size(); i++) {
      String host = examined.get(i);
      List<Signal> all = new ArrayList<>(signals.getOrDefault(host, List.of()));
      if (i < MAX_EXAMINED) {
        all.addAll(behaviourSignals(host, pairs, conversations.distinctAnsweredPorts(fileId, host),
            observed.getOrDefault(host, List.of())));
      }
      HostRole inferred = decide(host, all, analyst.getOrDefault(host, List.of()));
      Optional<HumanOverrideEntity> o = overrides.find(QUESTION, fileId, host);
      if (o.isEmpty() && !analyst.containsKey(host) && inferred.label() == null && all.size() < 2) {
        single++;
        continue;
      }
      out.add(o.map(x -> overridden(inferred, x.getLabel(), x.getRationale(), x.getActor()))
          .orElse(inferred));
    }
    out.sort(Comparator.comparing((HostRole r) -> !r.isHoneypot())
        .thenComparing(r -> -r.confidence()).thenComparing(HostRole::host));
    return new HoneypotReport(List.copyOf(out), single, observed.size(), file.version());
  }

  // ── What each server said ─────────────────────────────────────────────────────────────────

  /** Per server: each (kind, value, port) it sent, banners and certificates both. */
  private Map<String, List<String[]>> observations(UUID fileId) {
    Map<String, List<String[]>> out = new LinkedHashMap<>();
    for (Banner b : banners.banners(fileId)) {
      out.computeIfAbsent(b.ip(), k -> new ArrayList<>())
          .add(new String[] {b.kind(), b.value(), Integer.toString(b.port())});
    }
    Set<String> seenCerts = new HashSet<>();
    for (ConversationFacts c : conversations.tlsConversations(fileId)) {
      var flow = c.flow();
      var tls = c.tls();
      if (tls == null || (tls.tlsSubject() == null && tls.tlsIssuer() == null)) continue;
      // The server is the side that didn't open it; without a handshake, the destination.
      boolean dstOpened = flow.initiatorIp() != null && flow.initiatorIp().equals(flow.dstIp());
      String server = dstOpened ? flow.srcIp() : flow.dstIp();
      Integer port = dstOpened ? flow.srcPort() : flow.dstPort();
      String cert = "subject " + nz(tls.tlsSubject()) + "; issuer " + nz(tls.tlsIssuer());
      if (server != null && seenCerts.add(server + "|" + port + "|" + cert)) {
        out.computeIfAbsent(server, k -> new ArrayList<>())
            .add(new String[] {"tls-cert", cert, port == null ? "" : port.toString()});
      }
    }
    return out;
  }

  /** The signatures one server matched, each once, strongest first. */
  static List<Signal> signatureSignals(List<String[]> seen, List<Signature> signatures) {
    Map<String, Signal> out = new LinkedHashMap<>();
    for (Signature s : signatures) {
      for (String[] o : seen) {
        if (!s.kind().equals(o[0]) || !s.matches(o[1]) || out.containsKey(s.id())) continue;
        String port = o[2].isEmpty() ? "" : " on port " + o[2];
        out.put(s.id(), new Signal("signature", s.id(), s.honeypot(), s.strength().name(),
            s.strength().points, KIND_LABEL.getOrDefault(s.kind(), s.kind()) + " \"" + o[1] + "\"" + port
                + ": " + s.why()));
      }
    }
    return out.values().stream()
        .sorted(Comparator.comparingInt(Signal::points).reversed()).toList();
  }

  private static final Map<String, String> KIND_LABEL = Map.of(
      "ssh-banner", "SSH banner",
      "ssh-hassh", "SSH key exchange (HASSH)",
      "ftp-banner", "FTP greeting",
      "http-server", "HTTP Server header",
      "smb-os", "SMB native OS",
      "smb-server-name", "SMB server name",
      "mysql-version", "MySQL version",
      "tls-cert", "TLS certificate");

  // ── How it behaves ────────────────────────────────────────────────────────────────────────

  static List<Signal> behaviourSignals(String host, List<HostPair> pairs, long answeredPorts,
      List<String[]> seen) {
    List<Signal> out = new ArrayList<>();
    long opened = 0, answered = 0;
    Set<String> openers = new HashSet<>();
    for (HostPair p : pairs) {
      if (host.equals(p.a())) {
        opened += p.openedByA();
        answered += p.openedByB();
        if (p.openedByB() > 0) openers.add(p.b());
      } else if (host.equals(p.b())) {
        opened += p.openedByB();
        answered += p.openedByA();
        if (p.openedByA() > 0) openers.add(p.a());
      }
    }
    long known = opened + answered;
    if (openers.size() >= FAN_IN_OPENERS && known > 0 && (double) opened / known <= FAN_OUT_SHARE) {
      out.add(new Signal("behaviour", "fan-in", null, Strength.WEAK.name(), Strength.WEAK.points,
          openers.size() + " hosts opened " + answered + " conversations to it; it opened "
              + (opened == 0 ? "none" : opened) + ": a decoy draws connections and starts none"));
    }
    if (answeredPorts >= MANY_PORTS) {
      out.add(new Signal("behaviour", "many-services", null, Strength.MEDIUM.name(),
          Strength.MEDIUM.points, "it answered on " + answeredPorts
              + " ports: a real server exposes a few, a low-interaction honeypot emulates many"));
    }
    // A Windows SMB server answering with a Unix stack's TTL: what Dionaea, on Linux, looks like.
    boolean windowsSmb = seen.stream().anyMatch(o -> "smb-os".equals(o[0]) && o[1].startsWith("Windows"));
    boolean unixTtl = seen.stream().anyMatch(o -> "ttl".equals(o[0]) && "64".equals(o[1]));
    boolean windowsTtl = seen.stream().anyMatch(o -> "ttl".equals(o[0]) && "128".equals(o[1]));
    if (windowsSmb && unixTtl && !windowsTtl) {
      out.add(new Signal("behaviour", "os-mismatch", null, Strength.WEAK.name(), Strength.WEAK.points,
          "its SMB says Windows, but its packets start with TTL 64, as Linux and Unix stacks do"
              + " (Windows uses 128; Samba on Linux would do this too)"));
    }
    return out;
  }

  // ── The vote ──────────────────────────────────────────────────────────────────────────────

  /** The machine's verdict on one host, after analyst evidence adds its weight. */
  static HostRole decide(String host, List<Signal> signals, List<ManualEvidenceEntity> analyst) {
    int machine = Math.min(100, signals.stream().mapToInt(Signal::points).sum());
    boolean signature = signals.stream().anyMatch(s -> "signature".equals(s.source()));
    String honeypot = named(signals);
    List<String> reasons = new ArrayList<>(signals.stream().map(Signal::text).toList());
    int forIt = machine, against = 0;
    List<String> againstReasons = new ArrayList<>();
    List<Signal> all = new ArrayList<>(signals);
    String ownLabel = null;
    for (ManualEvidenceEntity e : analyst) {
      String label = e.getLabel() == null ? HONEYPOT : e.getLabel().trim();
      String text = "analyst evidence: " + e.getReason();
      if (NOT_HONEYPOT.equalsIgnoreCase(label) || "not".equalsIgnoreCase(label)) {
        against += e.getWeight();
        againstReasons.add(text);
      } else {
        forIt += e.getWeight();
        reasons.add(text);
        if (!HONEYPOT.equalsIgnoreCase(label)) ownLabel = label;
        all.add(new Signal("analyst", "evidence", null, null, e.getWeight(), text));
      }
    }
    forIt = Math.min(100, forIt);
    against = Math.min(100, against);
    boolean analystFor = all.size() > signals.size();
    // Two signals, one a signature (or an analyst's word), and enough points between them.
    boolean concluded = all.size() >= 2 && (signature || analystFor) && forIt >= CONCLUDE
        && forIt > against;

    List<Candidate> candidates = new ArrayList<>();
    if (forIt > 0) candidates.add(new Candidate(HONEYPOT, forIt, List.copyOf(reasons)));
    if (against > 0) candidates.add(new Candidate(NOT_HONEYPOT, against, List.copyOf(againstReasons)));
    candidates.sort(Comparator.comparingInt(Candidate::score).reversed());
    boolean contested = candidates.size() > 1
        && candidates.get(0).score() - candidates.get(1).score() < CONTESTED_MARGIN;

    if (against > forIt && against > 0) {
      return new HostRole(host, NOT_HONEYPOT, null, "HUMAN", against, contested, candidates, all,
          String.join("; ", againstReasons), null);
    }
    if (!concluded) {
      return new HostRole(host, null, honeypot, "MACHINE", forIt, contested, candidates, all,
          notEnough(all, signature, forIt), null);
    }
    String basis = signals.isEmpty() ? "HUMAN" : "MACHINE";
    return new HostRole(host, ownLabel != null && signals.isEmpty() ? ownLabel : HONEYPOT, honeypot,
        basis, Math.min(95, forIt), contested, candidates, all, String.join("; ", reasons), null);
  }

  /** Why a host's signals fall short. */
  static String notEnough(List<Signal> signals, boolean signature, int points) {
    if (signals.size() < 2) {
      return "one signal only, and a real server can show it too: a honeypot needs two";
    }
    if (!signature) return "how it behaves fits a decoy, but nothing it sent matches a honeypot";
    return "its signals add up to " + points + " points of the " + CONCLUDE + " a honeypot needs";
  }

  /** The honeypot the strongest signatures name, by their points. */
  static String named(List<Signal> signals) {
    Map<String, Integer> byName = new LinkedHashMap<>();
    signals.stream().filter(s -> s.honeypot() != null)
        .forEach(s -> byName.merge(s.honeypot(), s.points(), Integer::sum));
    return byName.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey)
        .orElse(null);
  }

  /** An analyst's answer, which wins outright; the machine's candidates and signals stay. */
  static HostRole overridden(HostRole inferred, String label, String rationale, String actor) {
    String l = label == null ? HONEYPOT : label.trim();
    String shown = HONEYPOT.equalsIgnoreCase(l) ? HONEYPOT
        : NOT_HONEYPOT.equalsIgnoreCase(l) ? NOT_HONEYPOT : l;
    String reason = rationale == null || rationale.isBlank() ? "set by an analyst" : rationale.trim();
    return new HostRole(inferred.host(), shown, NOT_HONEYPOT.equals(shown) ? null : inferred.honeypot(),
        "HUMAN", 100, false, inferred.candidates(), inferred.signals(), reason, actor);
  }

  // ── The signature file ────────────────────────────────────────────────────────────────────

  SignatureFile signatures() {
    SignatureFile f = signatureFile;
    if (f == null) {
      f = load(mapper);
      signatureFile = f;
    }
    return f;
  }

  static SignatureFile load(ObjectMapper mapper) {
    try (InputStream in = HoneypotRoleService.class.getClassLoader().getResourceAsStream(SIGNATURES)) {
      if (in == null) throw new IllegalStateException(SIGNATURES + " is missing");
      JsonNode root = mapper.readTree(in);
      List<Signature> out = new ArrayList<>();
      Set<String> ids = new LinkedHashSet<>();
      for (JsonNode s : root.path("signatures")) {
        String id = s.path("id").asText();
        if (!ids.add(id)) throw new IllegalStateException("duplicate honeypot signature " + id);
        out.add(new Signature(id, s.path("honeypot").asText(), s.path("kind").asText(),
            s.path("match").asText("equals"), s.path("value").asText(),
            Strength.valueOf(s.path("strength").asText().toUpperCase(java.util.Locale.ROOT)),
            s.path("why").asText()));
      }
      return new SignatureFile(root.path("version").asText(null), List.copyOf(out));
    } catch (java.io.IOException e) {
      throw new IllegalStateException("unreadable " + SIGNATURES, e);
    }
  }

  private static String nz(String s) {
    return s == null ? "" : s;
  }
}
