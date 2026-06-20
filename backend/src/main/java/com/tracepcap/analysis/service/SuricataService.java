package com.tracepcap.analysis.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.entity.ConversationEntity;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
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
 * <p>Uses: {@code suricata -r <file> -l <outdir>} with the bundled Emerging Threats Open ruleset.
 * Suricata writes one JSON object per line to {@code <outdir>/eve.json}; this service reads the
 * {@code alert} events and maps each back to a {@link PcapParserService.ConversationInfo} by its
 * 5-tuple.
 *
 * <p>Each alert is rendered to a compact string ({@code "<signature> (sid:<id>, sev:<n>)"}) and
 * stored in the conversation's {@code suricataAlerts} list, mirroring how {@link NdpiService}
 * populates {@code flowRisks}.
 *
 * <p>Gracefully degrades: if the {@code suricata} binary or ruleset is missing or Suricata fails,
 * {@code suricataAlerts} stays empty and analysis continues normally.
 */
@Slf4j
@Service
public class SuricataService {

  private static final String SURICATA_BINARY = "suricata";

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

    Map<String, Set<String>> alertMap = runSuricata(pcapFile);
    if (alertMap.isEmpty()) return;

    for (PcapParserService.ConversationInfo conv : conversations) {
      Set<String> alerts = resolve(alertMap, conv);
      if (alerts != null && !alerts.isEmpty()) {
        conv.setSuricataAlerts(new ArrayList<>(alerts));
      }
    }

    long enriched = conversations.stream().filter(c -> !c.getSuricataAlerts().isEmpty()).count();
    log.info("Suricata flagged {}/{} conversations with IDS alerts", enriched, conversations.size());
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  /**
   * Runs {@code suricata -r <file> -l <tmp>} and returns a map of flow key → set of alert strings.
   * The output directory is created per-run and deleted afterwards.
   */
  private Map<String, Set<String>> runSuricata(File pcapFile) {
    Map<String, Set<String>> result = new HashMap<>();
    Path outDir = null;

    try {
      outDir = Files.createTempDirectory("suricata-");

      // --runmode single: one packet-processing thread. Suricata otherwise spawns one worker per
      //   CPU core, each pre-allocating large stream/flow pools — which exhausts memory and aborts
      //   on many-core hosts for a one-shot offline read.
      // --set unix-command.enabled=no: the non-root runtime user cannot bind the root-owned command
      //   socket, and it is not needed for offline pcap-read mode.
      ProcessBuilder pb =
          new ProcessBuilder(
              SURICATA_BINARY,
              "-r",
              pcapFile.getAbsolutePath(),
              "-l",
              outDir.toAbsolutePath().toString(),
              "--runmode",
              "single",
              "--set",
              "unix-command.enabled=no");

      Process process = pb.start();

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

      parseEveJson(outDir.resolve(EVE_JSON), result);
      log.debug("Suricata produced alerts for {} distinct flows", result.size());

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
  private void parseEveJson(Path eveJson, Map<String, Set<String>> result) {
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

  /** Parse a single eve.json line; only {@code event_type == "alert"} objects contribute. */
  private void parseEveLine(String line, Map<String, Set<String>> result) {
    if (line == null || line.isBlank()) return;
    try {
      JsonNode root = objectMapper.readTree(line);
      if (!"alert".equals(root.path("event_type").asText())) return;

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
      result.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(formatted);
    } catch (Exception e) {
      log.debug("Skipping unparseable eve.json line: {}", e.getMessage());
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

  /** Lookup alerts trying both directions (src→dst and dst→src). */
  private Set<String> resolve(
      Map<String, Set<String>> alertMap, PcapParserService.ConversationInfo conv) {
    String key1 =
        flowKey(
            conv.getSrcIp(),
            conv.getSrcPort(),
            conv.getDstIp(),
            conv.getDstPort(),
            conv.getProtocol());
    Set<String> alerts = alertMap.get(key1);
    if (alerts == null) {
      String key2 =
          flowKey(
              conv.getDstIp(),
              conv.getDstPort(),
              conv.getSrcIp(),
              conv.getSrcPort(),
              conv.getProtocol());
      alerts = alertMap.get(key2);
    }
    return alerts;
  }

  /**
   * Canonical 5-tuple key. The transport protocol is intentionally ignored (set to "") because
   * Suricata's {@code proto} field ("TCP"/"UDP") and pcap4j's {@code protocol} string may differ in
   * casing/naming; IP+port pairs are unique enough to map an alert to its conversation.
   */
  private String flowKey(String ip, Integer port, String ip2, Integer port2, String proto) {
    return String.format("%s:%s->%s:%s", ip, port, ip2, port2);
  }

  /** Drains a process stream on a daemon thread so the subprocess never blocks on a full pipe. */
  private Thread drainAsync(java.io.InputStream stream, String label) {
    Thread t =
        new Thread(
            () -> {
              try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
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
}
