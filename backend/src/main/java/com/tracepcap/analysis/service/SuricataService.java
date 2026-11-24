package com.tracepcap.analysis.service;

import com.tracepcap.analysis.spi.ExtractionManifest;
import com.tracepcap.analysis.spi.ExtractionTarget;
import com.tracepcap.analysis.spi.Extractor;
import com.tracepcap.common.stage.Tier;
import org.springframework.beans.factory.annotation.Value;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.entity.ConversationEntity;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Runs Suricata in offline pcap-read mode as a subprocess to perform signature-based threat
 * detection over each uploaded PCAP, complementing nDPI: where nDPI answers <em>"what is this
 * traffic?"</em>, Suricata answers <em>"is this traffic a known threat?"</em>.
 *
 * <p>Prefers a warm engine kept across analyses ({@link SuricataEngine}, #569) and falls back to
 * {@code suricata -r <file> -l <outdir>} per file. Either way the bundled Emerging Threats Open
 * ruleset is used and the output is the same eve.json.
 * Suricata writes one JSON object per line to {@code <outdir>/eve.json}; this service reads the
 * {@code alert} events and maps each back to a {@link PcapParserService.ConversationInfo} by its
 * 5-tuple.
 *
 * <p>Each alert is rendered to a compact string ({@code "<signature> (sid:<id>, sev:<n>)"}) and
 * stored in the conversation's {@code suricataAlerts} list, mirroring how {@link NdpiService}
 * populates {@code flowRisks}.
 *
 * <p>The same eve.json carries a {@code tls} record per TLS session (#599). Those fill the TLS facts
 * nDPI didn't provide: above all the client JA3, which nDPI 6 no longer reports (it reports JA4
 * instead), plus SNI and certificate fields where nDPI missed them, and the negotiated version,
 * which nothing else records. They only ever fill gaps; a value nDPI set is never replaced. The
 * {@code http}, {@code dns} and HTTP {@code fileinfo} records are deliberately not read: tshark
 * already extracts those (web server log, DNS query log, file extraction). The {@code smb}, {@code
 * dcerpc} and SMB {@code fileinfo} records are, by {@link SmbRpcRecords} (#1266).
 *
 * <p>Gracefully degrades: if the {@code suricata} binary or ruleset is missing or Suricata fails,
 * {@code suricataAlerts} stays empty and analysis continues normally.
 */
@Slf4j
@Service
public class SuricataService implements Extractor {

  /**
   * Global kill-switch. Lived in AnalysisService as a field the pipeline checked before calling
   * this service; it belongs here, because "when do I run" is the module's business and a runner
   * that knew about it would be a core to edit (#512).
   */
  @Value("${tracepcap.suricata.enabled:true}")
  private boolean suricataEnabled;

  /** Warm engine (#569). Falls back to the per-file subprocess below when unavailable. */
  private final SuricataEngine engine;

  /** Which ruleset to load (#600). Absent in unit tests, where the packaged default applies. */
  @org.springframework.beans.factory.annotation.Autowired(required = false)
  private SuricataRuleset ruleset;

  public SuricataService(SuricataEngine engine) {
    this.engine = engine;
  }

  @Override
  public String name() {
    return ExtractionManifest.SURICATA;
  }

  @Override
  public Tier tier() {
    // Suricata's rules are a third party's judgment about traffic — deterministic to run, heuristic
    // in what they conclude. The facts it writes are INFERRED; the tool itself is not an LLM.
    return Tier.DETERMINISTIC;
  }

  @Override
  public String manifestKey() {
    return ExtractionManifest.SURICATA;
  }

  /**
   * Both gates, and the module owns both: the per-file toggle chosen at upload, and the deployment
   * kill-switch. SURICATA_ENABLED=false disables it across the board regardless of the upload flag.
   */
  @Override
  public boolean enabledFor(ExtractionTarget target) {
    return suricataEnabled && target.file().isEnableSuricata();
  }

  @Override
  public Outcome extract(ExtractionTarget target) {
    if (target.conversations().isEmpty()) return Outcome.completed("suricata ran");
    Eve eve = runSuricata(target.capture());
    apply(eve, target.conversations());
    saveStats(target, eve);
    return Outcome.completed("suricata ran");
  }

  /** The engine run (the slow part) needs only the file, so it happens before the pipeline's transaction (#409). */
  @Override
  public Prepared prepare(ExtractionTarget target) {
    Eve eve = runSuricata(target.capture());
    return conversations -> {
      apply(eve, conversations);
      saveStats(target, eve);
      return Outcome.completed("suricata ran");
    };
  }

  /** What one Suricata run produced: alerts and TLS records, each keyed by flow (both directions). */
  record Eve(
      Map<String, Set<String>> alerts,
      Map<String, TlsRecord> tls,
      Map<String, List<AlertEvent>> alertEvents,
      java.util.concurrent.atomic.AtomicInteger alertEventCount,
      Map<String, List<Anomaly>> anomalies,
      java.util.concurrent.atomic.AtomicInteger anomalyCount,
      java.util.concurrent.atomic.AtomicReference<CaptureStats> stats,
      Map<String, List<SmbRpcRecords.Op>> remoteOps,
      java.util.concurrent.atomic.AtomicInteger remoteOpCount,
      Map<String, String> smbTrees,
      Map<String, List<KerberosRecords.Reply>> kerberos,
      java.util.concurrent.atomic.AtomicInteger kerberosCount,
      Map<String, JsonNode> kerberosRequests,
      Map<String, Integer> alertTotals) {
    static Eve empty() {
      return new Eve(new HashMap<>(), new HashMap<>(), new HashMap<>(),
          new java.util.concurrent.atomic.AtomicInteger(), new HashMap<>(),
          new java.util.concurrent.atomic.AtomicInteger(),
          new java.util.concurrent.atomic.AtomicReference<>(), new HashMap<>(),
          new java.util.concurrent.atomic.AtomicInteger(), new HashMap<>(), new HashMap<>(),
          new java.util.concurrent.atomic.AtomicInteger(), new HashMap<>(), new HashMap<>());
    }
  }

  /**
   * One eve.json {@code anomaly} record (#1268): traffic a protocol parser found malformed or
   * one-sided, e.g. {@code applayer / proto_detect / APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION}.
   */
  public record Anomaly(
      java.time.LocalDateTime time, String srcIp, String dstIp, String type, String layer,
      String appProto, String event) {}

  /**
   * Suricata's counters for one run (#1268), from its {@code stats} record. Per capture in both
   * per-file and socket mode (measured: the same capture twice through one engine gave the same
   * counts).
   */
  public record CaptureStats(
      Long packets, Long invalidPackets, Long tcpSessions, Long reassemblyGaps,
      Long streamDepthReached, Long memcapDrops) {}

  /** At most this many anomaly records are kept per capture. */
  static final int MAX_ANOMALIES = 5_000;

  /** Saves a run's counters; optional so tests can build the service without persistence. */
  private IdsAlertWriter statsSink;

  @org.springframework.beans.factory.annotation.Autowired(required = false)
  void setStatsSink(IdsAlertWriter statsSink) {
    this.statsSink = statsSink;
  }

  private void saveStats(ExtractionTarget target, Eve eve) {
    CaptureStats s = eve.stats().get();
    if (s == null || statsSink == null || target.file() == null || target.file().getId() == null) return;
    try {
      statsSink.saveStats(com.tracepcap.analysis.entity.CaptureStatsEntity.builder()
          .fileId(target.file().getId())
          .packets(s.packets())
          .invalidPackets(s.invalidPackets())
          .tcpSessions(s.tcpSessions())
          .reassemblyGaps(s.reassemblyGaps())
          .streamDepthReached(s.streamDepthReached())
          .memcapDrops(s.memcapDrops())
          .build());
    } catch (Exception e) {
      log.warn("Saving Suricata's capture counters failed: {}", e.getMessage());
    }
  }

  /**
   * At most this many alert records are kept per capture (#1265). A scan or a noisy rule can fire
   * hundreds of thousands of times; the deduplicated message lists are unaffected by the cap, and
   * every flow's true count is kept beside the records (#1284).
   */
  static final int MAX_ALERT_EVENTS = 20_000;

  /**
   * At most this many alert records are kept per flow, each direction its own (#1284), so one noisy connection can't use up
   * the capture's budget and leave the conversations after it with none.
   */
  static final int MAX_ALERT_EVENTS_PER_FLOW = 100;

  /**
   * One eve.json {@code alert} record in full (#1265): when it fired, the packet's direction, the
   * rule's metadata, and the HTTP request it fired on. Every field but sid and signature may be null.
   */
  public record AlertEvent(
      java.time.LocalDateTime time,
      String srcIp,
      Integer srcPort,
      String dstIp,
      Integer dstPort,
      long sid,
      Integer gid,
      Integer rev,
      String signature,
      String category,
      Integer severity,
      Map<String, List<String>> metadata,
      String httpMethod,
      String httpHost,
      String httpUrl,
      String httpUserAgent,
      Integer httpStatus) {

    /** The first value of one metadata key ("signature_severity" → "Major"), or null. */
    public String meta(String key) {
      List<String> v = metadata == null ? null : metadata.get(key);
      return v == null || v.isEmpty() ? null : v.get(0);
    }
  }

  /** The TLS facts from one eve.json {@code tls} record (#599). Every field may be null. */
  record TlsRecord(
      String sni,
      String subject,
      String issuer,
      java.time.LocalDateTime notBefore,
      java.time.LocalDateTime notAfter,
      String version,
      String ja3,
      String ja3s,
      com.tracepcap.analysis.spi.ConversationLookup.CertFacts cert) {

    /** Without the parsed certificate (#1235). */
    TlsRecord(
        String sni, String subject, String issuer, java.time.LocalDateTime notBefore,
        java.time.LocalDateTime notAfter, String version, String ja3, String ja3s) {
      this(sni, subject, issuer, notBefore, notAfter, version, ja3, ja3s, null);
    }
  }

  private static final String SURICATA_BINARY = "suricata";

  /**
   * Turns JA3/JA3S hashing on (#1235). The image enables the {@code tls} custom field list so the
   * certificate and chain are logged, and with a custom list Suricata only computes JA3 when
   * something asks for it, which would silently drop the client JA3 that #599 reads.
   */
  static final String JA3_ON = "app-layer.protocols.tls.ja3-fingerprints=yes";

  /**
   * Inspects TCP streams that were already open when the capture began (#1266). Suricata's default
   * ignores a stream without its handshake: no protocol parsing and no alerts. A live sensor sees
   * every handshake, but a capture is a slice: on PCAP-ATTACK's PsExec and smbexec samples (no SYN)
   * this is the difference between nothing and "ET INFO PsExec service created".
   */
  static final String MIDSTREAM_ON = "stream.midstream=true";

  /**
   * Doesn't drop packets for a bad TCP/IP checksum (as {@code -k none} does), the settings Suricata
   * itself uses for pcap reading and stream reassembly. A capture taken on the sending host has the
   * checksums its network card would have filled in (offload), and Suricata's default, "auto", only
   * notices that statistically: on a short capture, too late. Until then it leaves those packets
   * out of stream and protocol inspection, so PCAP-ATTACK's SpoolSample capture produced no alerts
   * and no SMB records in the warm engine, against 6 and 22 with this. The capture is a record of
   * what was sent; it isn't the network's job to check it here.
   */
  static final String NO_CHECKSUM_DROP_PCAP = "pcap-file.checksum-checks=no";
  static final String NO_CHECKSUM_DROP_STREAM = "stream.checksum-validation=no";

  /**
   * The analysis settings both ways of running Suricata share, the warm engine and the per-file
   * fallback, as {@code --set} pairs. One list so the two can't drift: a capture would otherwise get
   * different alerts depending on which path happened to run it.
   */
  static final List<String> SHARED_SETTINGS = List.of(
      "--set", JA3_ON, "--set", MIDSTREAM_ON,
      "--set", NO_CHECKSUM_DROP_PCAP, "--set", NO_CHECKSUM_DROP_STREAM);

  /** Suricata writes its JSON event log here, relative to the {@code -l} output directory. */
  private static final String EVE_JSON = "eve.json";

  private final ObjectMapper objectMapper = new ObjectMapper();

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Enrich each ConversationInfo with Suricata IDS alerts. Runs {@code suricata -r} exactly once and
   * resolves alerts to conversations by 5-tuple. Conversations with no matching alert are left with
   * an empty suricataAlerts list.
   */
  public void enrich(File pcapFile, List<PcapParserService.ConversationInfo> conversations) {
    if (conversations.isEmpty()) return;
    apply(runSuricata(pcapFile), conversations);
  }

  /** Resolves alerts and TLS records onto conversations by 5-tuple. Shared by {@link #enrich} and {@link #prepare}. */
  void apply(Eve eve, List<PcapParserService.ConversationInfo> conversations) {
    if (conversations.isEmpty()) return;
    int filled = 0;
    // One flow key can match several conversations (DHCP clients split by MAC): each SMB/RPC
    // operation goes to the first, so none is stored and counted twice.
    Set<SmbRpcRecords.Op> opsGiven = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
    Set<KerberosRecords.Reply> kerberosGiven = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
    Set<String> totalsGiven = new java.util.HashSet<>();
    for (PcapParserService.ConversationInfo conv : conversations) {
      Set<String> alerts = both(eve.alerts(), conv, LinkedHashSet::new);
      if (alerts != null && !alerts.isEmpty()) {
        conv.setSuricataAlerts(new ArrayList<>(alerts));
      }
      List<Anomaly> anomalies = both(eve.anomalies(), conv, ArrayList::new);
      if (!anomalies.isEmpty()) conv.setSuricataAnomalies(anomalies);
      List<KerberosRecords.Reply> krb = both(eve.kerberos(), conv, ArrayList::new);
      krb.removeIf(r -> !kerberosGiven.add(r));
      if (!krb.isEmpty()) {
        conv.setKerberosExchanges(KerberosRecords.group(
            krb, conv.getSrcIp(), conv.getSrcPort(), conv.getDstIp(), conv.getDstPort()));
      }
      List<SmbRpcRecords.Op> ops = both(eve.remoteOps(), conv, ArrayList::new);
      ops.removeIf(o -> !opsGiven.add(o));
      if (!ops.isEmpty()) {
        conv.setRemoteOperations(SmbRpcRecords.group(
            ops, conv.getSrcIp(), conv.getSrcPort(), conv.getDstIp(), conv.getDstPort(),
            conv.getInitiatorIp()));
      }
      // A flow's count goes to the first conversation on it, as its records do when they're saved.
      conv.setIdsAlertTotal(totalOnce(eve.alertTotals(), conv, totalsGiven));
      List<AlertEvent> events = both(eve.alertEvents(), conv, ArrayList::new);
      if (!events.isEmpty()) {
        events.sort(Comparator.comparing(AlertEvent::time, Comparator.nullsLast(Comparator.naturalOrder())));
        conv.setIdsAlertEvents(events);
      }
      TlsRecord tls = resolve(eve.tls(), conv);
      if (tls != null && fillTls(conv, tls)) filled++;
    }
    long enriched = conversations.stream().filter(c -> !c.getSuricataAlerts().isEmpty()).count();
    log.info(
        "Suricata flagged {}/{} conversations with IDS alerts; TLS records filled facts on {}",
        enriched, conversations.size(), filled);
  }

  /**
   * Fills the conversation's TLS facts Suricata knows and nDPI didn't provide. Never replaces a
   * value: nDPI's stays when both have one. Returns whether anything was filled.
   */
  static boolean fillTls(PcapParserService.ConversationInfo conv, TlsRecord t) {
    boolean any = false;
    if (conv.getJa3Client() == null && t.ja3() != null) { conv.setJa3Client(t.ja3()); any = true; }
    if (conv.getJa3Server() == null && t.ja3s() != null) { conv.setJa3Server(t.ja3s()); any = true; }
    if (isBlank(conv.getHostname()) && t.sni() != null) { conv.setHostname(t.sni()); any = true; }
    if (conv.getTlsSubject() == null && t.subject() != null) { conv.setTlsSubject(t.subject()); any = true; }
    if (conv.getTlsIssuer() == null && t.issuer() != null) { conv.setTlsIssuer(t.issuer()); any = true; }
    if (conv.getTlsNotBefore() == null && t.notBefore() != null) { conv.setTlsNotBefore(t.notBefore()); any = true; }
    if (conv.getTlsNotAfter() == null && t.notAfter() != null) { conv.setTlsNotAfter(t.notAfter()); any = true; }
    if (conv.getTlsVersion() == null && t.version() != null) { conv.setTlsVersion(t.version()); any = true; }
    // The certificate's own detail (#1235): only Suricata has it, so it's set whenever present.
    if (conv.getTlsCert() == null && t.cert() != null) { conv.setTlsCert(t.cert()); any = true; }
    return any;
  }

  private static boolean isBlank(String s) {
    return s == null || s.isBlank();
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  /**
   * Runs {@code suricata -r <file> -l <tmp>} and returns a map of flow key → set of alert strings.
   * The output directory is created per-run and deleted afterwards.
   */
  private Eve runSuricata(File pcapFile) {
    Eve result = Eve.empty();
    Path outDir = null;

    try {
      outDir = Files.createTempDirectory("suricata-");

      // --runmode single: one packet-processing thread. Suricata otherwise spawns one worker per
      //   CPU core, each pre-allocating large stream/flow pools — which exhausts memory and aborts
      //   on many-core hosts for a one-shot offline read.
      // --set unix-command.enabled=no: the non-root runtime user cannot bind the root-owned command
      //   socket, and it is not needed for offline pcap-read mode.
      // Warm engine first (#569): the ruleset build is ~45s and is otherwise paid per file, while
      // the packet processing itself is milliseconds. Identical alert output, measured 66x faster.
      if (engine.process(pcapFile, outDir)) {
        // Warm output lives in its own subdirectory so an abandoned warm run cannot interleave
        // with the cold fallback below.
        parseEveJson(SuricataEngine.warmDir(outDir).resolve(EVE_JSON), result);
        log.debug("Suricata (warm) produced alerts for {} flow keys, TLS records for {}", result.alerts().size(), result.tls().size());
        return result;
      }

      List<String> command =
          new ArrayList<>(
              List.of(
                  SURICATA_BINARY,
                  "-r",
                  pcapFile.getAbsolutePath(),
                  "-l",
                  outDir.toAbsolutePath().toString(),
                  "--runmode",
                  "single",
                  "--set",
                  "unix-command.enabled=no"));
      command.addAll(SHARED_SETTINGS);
      if (ruleset != null) command.addAll(ruleset.suricataArgs());
      ProcessBuilder pb = new ProcessBuilder(command);

      Process process = pb.start();
      try {
        Thread stdoutDrainer = drainAsync(process.getInputStream(), "stdout");
        Thread stderrDrainer = drainAsync(process.getErrorStream(), "stderr");
        stdoutDrainer.start();
        stderrDrainer.start();

        int exitCode = process.waitFor();
        stdoutDrainer.join();
        stderrDrainer.join();

        if (exitCode != 0) {
          log.warn("suricata exited with code {} — skipping IDS alerts", exitCode);
          return result;
        }

        engine.recordLoad(outDir.resolve("suricata.log"), "per-file run");
        parseEveJson(outDir.resolve(EVE_JSON), result);
        log.debug("Suricata produced alerts for {} flow keys, TLS records for {}", result.alerts().size(), result.tls().size());
      } finally {
        // Never leak the subprocess if waitFor was interrupted or parsing threw.
        if (process.isAlive()) process.destroyForcibly();
      }

    } catch (InterruptedException e) {
      // Restore the interrupted status so callers up the stack can react.
      Thread.currentThread().interrupt();
      log.warn("Suricata process execution was interrupted", e);
    } catch (Exception e) {
      if (isNotFoundError(e)) {
        log.warn(
            "suricata not found — skipping IDS threat detection. Install suricata to enable.");
      } else {
        log.warn("Suricata analysis failed", e);
      }
    } finally {
      if (outDir != null) deleteRecursively(outDir);
    }

    return result;
  }

  /**
   * Parse {@code eve.json} (one JSON object per line), collecting {@code alert} events into the
   * result map keyed by 5-tuple flow key (indexed in both directions for direction-independent
   * lookup).
   */
  private void parseEveJson(Path eveJson, Eve result) {
    if (!Files.isReadable(eveJson)) {
      log.warn("Suricata eve.json not found at {} — no alerts parsed", eveJson);
      return;
    }

    try (Stream<String> lines = Files.lines(eveJson)) {
      lines.forEach(line -> parseEveLine(line, result));
    } catch (Exception e) {
      log.warn("Failed to read Suricata eve.json: {}", e.getMessage());
    }
  }

  /** Parse a single eve.json line; {@code alert} and {@code tls} objects contribute. */
  void parseEveLine(String line, Eve result) {
    if (line == null || line.isBlank()) return;
    // Cheap pre-check: most lines are flow records, which we don't read.
    if (!line.contains("\"event_type\":\"alert\"") && !line.contains("\"event_type\":\"tls\"")
        && !line.contains("\"event_type\":\"anomaly\"") && !line.contains("\"event_type\":\"stats\"")
        && !SmbRpcRecords.mayBe(line) && !KerberosRecords.mayBe(line)) return;
    try {
      JsonNode root = objectMapper.readTree(line);
      String type = root.path("event_type").asText();
      if ("krb5".equals(type)) {
        String srcIp = root.path("src_ip").asText(null), dstIp = root.path("dest_ip").asText(null);
        if (srcIp == null || dstIp == null) return;
        String key = flowKey(srcIp, root.has("src_port") ? root.get("src_port").asInt() : null,
            dstIp, root.has("dest_port") ? root.get("dest_port").asInt() : null,
            root.path("proto").asText(null));
        KerberosRecords.read(root, key, result.kerberos(), result.kerberosCount(), result.kerberosRequests());
        return;
      }
      if ("smb".equals(type) || "dcerpc".equals(type)
          || ("fileinfo".equals(type) && "smb".equals(root.path("app_proto").asText()))) {
        String srcIp = root.path("src_ip").asText(null), dstIp = root.path("dest_ip").asText(null);
        if (srcIp == null || dstIp == null) return;
        String key = flowKey(srcIp, root.has("src_port") ? root.get("src_port").asInt() : null,
            dstIp, root.has("dest_port") ? root.get("dest_port").asInt() : null,
            root.path("proto").asText(null));
        SmbRpcRecords.read(root, type, key, result.remoteOps(), result.remoteOpCount(), result.smbTrees());
        return;
      }
      if ("tls".equals(type)) {
        parseTls(root, result.tls());
        return;
      }
      if ("anomaly".equals(type)) {
        parseAnomaly(root, result);
        return;
      }
      if ("stats".equals(type)) {
        result.stats().set(parseStats(root.path("stats")));
        return;
      }
      if (!"alert".equals(type)) return;

      JsonNode alert = root.path("alert");
      if (alert.isMissingNode()) return;

      String signature = alert.path("signature").asText("").trim();
      if (signature.isEmpty()) return;
      long sid = alert.path("signature_id").asLong(0);
      int severity = alert.path("severity").asInt(0);
      String formatted = formatAlert(signature, sid, severity);

      String srcIp = root.path("src_ip").asText(null);
      String dstIp = root.path("dest_ip").asText(null);
      if (srcIp == null || dstIp == null) return;
      Integer srcPort = root.has("src_port") ? root.get("src_port").asInt() : null;
      Integer dstPort = root.has("dest_port") ? root.get("dest_port").asInt() : null;
      String proto = root.path("proto").asText(null);

      String key = flowKey(srcIp, srcPort, dstIp, dstPort, proto);
      result.alerts().computeIfAbsent(key, k -> new LinkedHashSet<>()).add(formatted);
      // Every alert is counted; only the first of each flow's, and of the capture's, are kept (#1284).
      int seenOnFlow = result.alertTotals().merge(key, 1, Integer::sum);
      // A running count: summing every flow's list on each line made a noisy capture quadratic.
      if (seenOnFlow <= MAX_ALERT_EVENTS_PER_FLOW
          && result.alertEventCount().getAndIncrement() < MAX_ALERT_EVENTS) {
        result.alertEvents().computeIfAbsent(key, k -> new ArrayList<>())
            .add(alertEvent(root, alert, signature, sid, severity, srcIp, srcPort, dstIp, dstPort));
      }
    } catch (Exception e) {
      log.debug("Skipping unparseable eve.json line: {}", e.getMessage());
    }
  }

  private static AlertEvent alertEvent(
      JsonNode root, JsonNode alert, String signature, long sid, int severity, String srcIp,
      Integer srcPort, String dstIp, Integer dstPort) {
    Map<String, List<String>> metadata = new java.util.LinkedHashMap<>();
    alert.path("metadata").fields().forEachRemaining(e -> {
      List<String> values = new ArrayList<>();
      if (e.getValue().isArray()) e.getValue().forEach(v -> values.add(v.asText()));
      else values.add(e.getValue().asText());
      metadata.put(e.getKey(), values);
    });
    JsonNode http = root.path("http");
    return new AlertEvent(
        eveTime(root.path("timestamp").asText(null)),
        srcIp, srcPort, dstIp, dstPort, sid,
        alert.has("gid") ? alert.get("gid").asInt() : null,
        alert.has("rev") ? alert.get("rev").asInt() : null,
        signature,
        text(alert, "category", 255),
        severity == 0 ? null : severity,
        metadata,
        text(http, "http_method", 32),
        text(http, "hostname", 512),
        text(http, "url", 4096),
        text(http, "http_user_agent", 2048),
        http.has("status") ? http.get("status").asInt() : null);
  }

  private static void parseAnomaly(JsonNode root, Eve result) {
    JsonNode a = root.path("anomaly");
    String event = a.path("event").asText("").trim();
    String srcIp = root.path("src_ip").asText(null);
    String dstIp = root.path("dest_ip").asText(null);
    // Decoder anomalies on a lone packet have no flow to hang on: only flow-level ones are kept.
    if (event.isEmpty() || srcIp == null || dstIp == null) return;
    if (result.anomalyCount().getAndIncrement() >= MAX_ANOMALIES) return; // a running count, as for alerts
    Integer srcPort = root.has("src_port") ? root.get("src_port").asInt() : null;
    Integer dstPort = root.has("dest_port") ? root.get("dest_port").asInt() : null;
    String key = flowKey(srcIp, srcPort, dstIp, dstPort, root.path("proto").asText(null));
    String app = text(a, "app_proto", 64);
    if (app == null) app = text(root, "app_proto", 64);
    result.anomalies().computeIfAbsent(key, k -> new ArrayList<>()).add(new Anomaly(
        eveTime(root.path("timestamp").asText(null)), srcIp, dstIp, text(a, "type", 64),
        text(a, "layer", 64), app, event.length() > 255 ? event.substring(0, 255) : event));
  }

  /** The counters that say how complete the capture and the inspection were. */
  static CaptureStats parseStats(JsonNode s) {
    JsonNode tcp = s.path("tcp"), dec = s.path("decoder");
    long memcap = num(tcp, "ssn_memcap_drop") + num(tcp, "segment_memcap_drop")
        + num(s.path("flow"), "memcap");
    return new CaptureStats(
        dec.has("pkts") ? dec.get("pkts").asLong() : null,
        dec.has("invalid") ? dec.get("invalid").asLong() : null,
        tcp.has("sessions") ? tcp.get("sessions").asLong() : null,
        tcp.has("reassembly_gap") ? tcp.get("reassembly_gap").asLong() : null,
        tcp.has("stream_depth_reached") ? tcp.get("stream_depth_reached").asLong() : null,
        memcap);
  }

  private static long num(JsonNode n, String f) {
    return n.path(f).asLong(0);
  }

  private static final java.time.format.DateTimeFormatter EVE_TIME =
      java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ");

  /**
   * Eve's {@code timestamp} ("2024-11-26T05:08:49.123456+0000") as the local time the conversations'
   * own times use (the JVM zone, as {@code PcapParserService} converts packet times); null if absent.
   */
  static java.time.LocalDateTime eveTime(String ts) {
    if (ts == null || ts.isBlank()) return null;
    try {
      return java.time.LocalDateTime.ofInstant(
          java.time.OffsetDateTime.parse(ts, EVE_TIME).toInstant(), java.time.ZoneId.systemDefault());
    } catch (Exception e) {
      return null;
    }
  }

  /**
   * One {@code tls} record. Suricata 6 writes, under {@code tls}: {@code sni}, {@code subject},
   * {@code issuerdn}, {@code notbefore}/{@code notafter} (ISO local), {@code version} (e.g. "TLS 1.2")
   * and {@code ja3}/{@code ja3s} objects with a {@code hash}. A session can log more than one record;
   * the first value seen for a field is kept.
   */
  private void parseTls(JsonNode root, Map<String, TlsRecord> out) {
    JsonNode tls = root.path("tls");
    String srcIp = root.path("src_ip").asText(null);
    String dstIp = root.path("dest_ip").asText(null);
    if (tls.isMissingNode() || srcIp == null || dstIp == null) return;
    Integer srcPort = root.has("src_port") ? root.get("src_port").asInt() : null;
    Integer dstPort = root.has("dest_port") ? root.get("dest_port").asInt() : null;
    TlsRecord parsed =
        new TlsRecord(
            text(tls, "sni", ConversationEntity.HOSTNAME_MAX_LENGTH),
            text(tls, "subject", Integer.MAX_VALUE),
            text(tls, "issuerdn", Integer.MAX_VALUE),
            date(tls, "notbefore"),
            date(tls, "notafter"),
            text(tls, "version", ConversationEntity.TLS_VERSION_MAX_LENGTH),
            hash(tls.path("ja3")),
            hash(tls.path("ja3s")),
            TlsCertificateParser.parse(
                tls.path("certificate").asText(null),
                tls.path("chain").isArray() ? tls.path("chain").size() : 1));
    out.merge(flowKey(srcIp, srcPort, dstIp, dstPort, null), parsed, SuricataService::firstSeen);
  }

  private static TlsRecord firstSeen(TlsRecord a, TlsRecord b) {
    return new TlsRecord(
        a.sni() != null ? a.sni() : b.sni(),
        a.subject() != null ? a.subject() : b.subject(),
        a.issuer() != null ? a.issuer() : b.issuer(),
        a.notBefore() != null ? a.notBefore() : b.notBefore(),
        a.notAfter() != null ? a.notAfter() : b.notAfter(),
        a.version() != null ? a.version() : b.version(),
        a.ja3() != null ? a.ja3() : b.ja3(),
        a.ja3s() != null ? a.ja3s() : b.ja3s(),
        a.cert() != null ? a.cert() : b.cert());
  }

  private static String text(JsonNode node, String field, int max) {
    String v = node.path(field).asText("").trim();
    if (v.isEmpty()) return null;
    return v.length() > max ? v.substring(0, max) : v;
  }

  /** A JA3/JA3S object's 32-hex hash, or null. */
  private static String hash(JsonNode ja3) {
    String h = ja3.path("hash").asText("").trim().toLowerCase();
    return h.matches("[0-9a-f]{" + ConversationEntity.JA3_HASH_LENGTH + "}") ? h : null;
  }

  private static java.time.LocalDateTime date(JsonNode node, String field) {
    String v = node.path(field).asText("").trim();
    if (v.isEmpty()) return null;
    try {
      return java.time.LocalDateTime.parse(v);
    } catch (java.time.format.DateTimeParseException e) {
      return null;
    }
  }

  /**
   * Render a compact, length-bounded alert label, e.g. {@code "ET MALWARE X (sid:2014 sev:1)"}.
   *
   * <p>Commas are intentionally avoided (and any commas in the ET signature msg are replaced with
   * semicolons): these alert strings are surfaced as filter tokens that travel through the same
   * comma-delimited transport as nDPI risk types and custom signatures (both the API query param
   * and the URL filter state). A literal comma in the value would be mis-split into two bogus
   * tokens, so the stored label must be comma-free.
   */
  private String formatAlert(String signature, long sid, int severity) {
    StringBuilder sb = new StringBuilder(signature);
    if (sid > 0 || severity > 0) {
      sb.append(" (");
      if (sid > 0) sb.append("sid:").append(sid);
      if (severity > 0) {
        if (sid > 0) sb.append(' ');
        sb.append("sev:").append(severity);
      }
      sb.append(')');
    }
    String s = sb.toString().replace(',', ';');
    return s.length() > ConversationEntity.SURICATA_ALERT_MAX_LENGTH
        ? s.substring(0, ConversationEntity.SURICATA_ALERT_MAX_LENGTH)
        : s;
  }

  /**
   * A conversation's alerts from both directions. Suricata keys an alert by the packet that fired
   * it, so a rule on the server's reply ("Remote Admin Response") sits under the reverse key; taking
   * one direction only, as {@link #resolve} does, dropped those whenever the client side fired too.
   */
  static <E, C extends java.util.Collection<E>> C both(
      Map<String, ? extends java.util.Collection<E>> map,
      PcapParserService.ConversationInfo conv,
      java.util.function.Supplier<C> into) {
    C out = into.get();
    String t = transportOf(conv);
    String forward = flowKey(conv.getSrcIp(), conv.getSrcPort(), conv.getDstIp(), conv.getDstPort(), t);
    String reverse = flowKey(conv.getDstIp(), conv.getDstPort(), conv.getSrcIp(), conv.getSrcPort(), t);
    if (map.get(forward) != null) out.addAll(map.get(forward));
    if (!reverse.equals(forward) && map.get(reverse) != null) out.addAll(map.get(reverse));
    return out;
  }

  /** The alerts Suricata logged on this conversation's flow, both directions; 0 if another had them. */
  static int totalOnce(Map<String, Integer> totals, PcapParserService.ConversationInfo conv, Set<String> given) {
    String t = transportOf(conv);
    String forward = flowKey(conv.getSrcIp(), conv.getSrcPort(), conv.getDstIp(), conv.getDstPort(), t);
    String reverse = flowKey(conv.getDstIp(), conv.getDstPort(), conv.getSrcIp(), conv.getSrcPort(), t);
    int n = 0;
    if (totals.containsKey(forward) && given.add(forward)) n += totals.get(forward);
    if (!reverse.equals(forward) && totals.containsKey(reverse) && given.add(reverse)) n += totals.get(reverse);
    return n;
  }

  /** Looks up a flow's entry trying both directions (src→dst and dst→src). */
  private static <T> T resolve(Map<String, T> alertMap, PcapParserService.ConversationInfo conv) {
    String key1 =
        flowKey(
            conv.getSrcIp(),
            conv.getSrcPort(),
            conv.getDstIp(),
            conv.getDstPort(),
            transportOf(conv));
    T alerts = alertMap.get(key1);
    if (alerts == null) {
      String key2 =
          flowKey(
              conv.getDstIp(),
              conv.getDstPort(),
              conv.getSrcIp(),
              conv.getSrcPort(),
              transportOf(conv));
      alerts = alertMap.get(key2);
    }
    return alerts;
  }

  /**
   * Canonical 5-tuple key. The transport protocol is intentionally ignored (set to "") because
   * Suricata's {@code proto} field ("TCP"/"UDP") and pcap4j's {@code protocol} string may differ in
   * casing/naming; IP+port pairs are unique enough to map an alert to its conversation.
   */
  private static String flowKey(String ip, Integer port, String ip2, Integer port2, String proto) {
    return ip + ":" + port + "->" + ip2 + ":" + port2;
  }

  /** Drains a process stream on a daemon thread so the subprocess never blocks on a full pipe. */
  private Thread drainAsync(java.io.InputStream stream, String label) {
    Thread t =
        new Thread(
            () -> {
              try (BufferedReader reader =
                  new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                  log.debug("suricata {}: {}", label, line);
                }
              } catch (Exception ignored) {
              }
            });
    t.setDaemon(true);
    return t;
  }

  /** Recursively delete the per-run Suricata output directory; best-effort. */
  private void deleteRecursively(Path dir) {
    try (Stream<Path> paths = Files.walk(dir)) {
      paths.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
    } catch (Exception e) {
      log.debug("Could not clean up Suricata temp dir {}: {}", dir, e.getMessage());
    }
  }

  private boolean isNotFoundError(Exception e) {
    String msg = e.getMessage();
    return msg != null && (msg.contains("No such file") || msg.contains("error=2"));
  }

  /** The transport a flow record is matched by (TCP/UDP); the display label for older rows. */
  private static String transportOf(PcapParserService.ConversationInfo conv) {
    return conv.getTransport() != null ? conv.getTransport() : conv.getProtocol();
  }
}
