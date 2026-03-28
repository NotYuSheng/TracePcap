package com.tracepcap.analysis.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Runs ndpiReader as a subprocess to identify application-layer protocols (e.g. Zoom, WhatsApp,
 * Telegram) and security risk flags for each conversation in a PCAP file.
 *
 * <p>Uses: {@code ndpiReader -i <file> -v 2}
 *
 * <p>Per-flow lines (from -v 2) look like:
 * <pre>
 *   \t1\tUDP 192.168.1.77:28150 <-> 91.108.8.1:533  [proto: 185/Telegram][Encrypted]...
 *   \t2\tTCP 192.168.0.114:1137 <-> 192.168.0.193:21 [proto: 1/FTP_CONTROL]...[Risk: ** Clear-Text Credentials **** Unsafe Protocol **]...
 * </pre>
 *
 * <p>Risk names are extracted from {@code [Risk: ** Name1 **** Name2 **]} blocks and normalised
 * to lowercase-underscore form (e.g. {@code clear_text_credentials}).
 *
 * <p>Gracefully degrades: if ndpiReader is not available or fails, all appName / flowRisks fields
 * remain at their defaults and analysis continues normally.
 */
@Slf4j
@Service
public class NdpiService {

  private static final String NDPI_BINARY = "ndpiReader";

  /**
   * Matches per-flow lines from {@code ndpiReader -v 2}.
   * Groups: (1) l4proto  (2) srcIp  (3) srcPort  (4) dstIp  (5) dstPort  (6) protoField
   */
  private static final Pattern FLOW_LINE = Pattern.compile(
      "\\t\\d+\\t(TCP|UDP)\\s+" +
      "(\\[?[\\w:.]+]?):(\\d+)\\s+(?:<->|->)\\s+(\\[?[\\w:.]+]?):(\\d+)" +
      ".*?\\[proto:\\s*[\\d.]+/([^\\]]+)\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** Matches the entire [Risk: ...] block in a flow line. */
  private static final Pattern RISK_BLOCK = Pattern.compile(
      "\\[Risk:\\s*(.*?)\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** Matches individual risk names between ** markers inside a risk block. */
  private static final Pattern RISK_NAME = Pattern.compile("\\*\\*\\s*([^*]+?)\\s*\\*\\*");

  /** Matches the traffic category field, e.g. [cat: Download/7] → group(1) = "Download". */
  private static final Pattern CATEGORY = Pattern.compile(
      "\\[cat:\\s*([^/\\]]+)(?:/\\d+)?\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** Transport-only names that carry no application-layer signal. */
  private static final Set<String> SKIP_PROTOCOLS = Set.of(
      "TCP", "UDP", "ICMP", "ICMPv6", "Unknown", "UNKNOWN"
  );

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Enrich each ConversationInfo with the app name and security risk flags detected by nDPI.
   * Runs {@code ndpiReader} exactly once and populates both fields in a single pass.
   * Conversations nDPI cannot identify are left with appName == null and an empty risks list.
   */
  public void enrich(File pcapFile, List<PcapParserService.ConversationInfo> conversations) {
    if (conversations.isEmpty()) return;

    Map<String, FlowData> flowMap = runNdpi(pcapFile);
    if (flowMap.isEmpty()) return;

    for (PcapParserService.ConversationInfo conv : conversations) {
      FlowData data = resolve(flowMap, conv);
      if (data == null) continue;
      if (data.appName() != null) conv.setAppName(data.appName());
      if (!data.risks().isEmpty()) conv.setFlowRisks(data.risks());
      if (data.category() != null) conv.setCategory(data.category());
    }

    long enrichedApps       = conversations.stream().filter(c -> c.getAppName() != null).count();
    long enrichedRisks      = conversations.stream().filter(c -> !c.getFlowRisks().isEmpty()).count();
    long enrichedCategories = conversations.stream().filter(c -> c.getCategory() != null).count();
    log.info("nDPI enriched {}/{} with app names, {}/{} with risks, {}/{} with categories",
        enrichedApps, conversations.size(), enrichedRisks, conversations.size(),
        enrichedCategories, conversations.size());
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  /** Immutable holder for per-flow nDPI data extracted from one -v 2 line. */
  private record FlowData(String appName, List<String> risks, String category) {}

  /**
   * Runs {@code ndpiReader -i <file> -v 2} and returns a map of flow key → FlowData.
   * Each FlowData contains the detected app name (may be null) and list of risk names.
   */
  private Map<String, FlowData> runNdpi(File pcapFile) {
    Map<String, FlowData> result = new HashMap<>();

    ProcessBuilder pb = new ProcessBuilder(NDPI_BINARY, "-i", pcapFile.getAbsolutePath(), "-v", "2");

    try {
      Process process = pb.start();

      Thread stderrDrainer = new Thread(() -> {
        try (BufferedReader err =
            new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
          String line;
          while ((line = err.readLine()) != null) {
            log.debug("ndpiReader stderr: {}", line);
          }
        } catch (Exception ignored) {}
      });
      stderrDrainer.setDaemon(true);
      stderrDrainer.start();

      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null) {
          parseFlowLine(line, result);
        }
      }
      process.waitFor();
      log.debug("nDPI parsed {} distinct flows", result.size());

    } catch (Exception e) {
      if (isNotFoundError(e)) {
        log.warn("ndpiReader not found — skipping app/risk identification. Install libndpi-bin to enable.");
      } else {
        log.warn("nDPI analysis failed", e);
      }
    }

    return result;
  }

  /**
   * Parse one ndpiReader -v 2 flow line into the result map, extracting both app name and risks.
   *
   * <p>Proto field examples: "Telegram" → Telegram, "QUIC.Google" → Google, "MDNS" → MDNS
   * <p>Risk block example: {@code [Risk: ** Clear-Text Credentials **** Unsafe Protocol **]}
   */
  private void parseFlowLine(String line, Map<String, FlowData> result) {
    Matcher m = FLOW_LINE.matcher(line);
    if (!m.find()) return;

    String l4proto = m.group(1).toUpperCase();
    String srcIp   = stripBrackets(m.group(2));
    int    srcPort = Integer.parseInt(m.group(3));
    String dstIp   = stripBrackets(m.group(4));
    int    dstPort = Integer.parseInt(m.group(5));

    // App name from proto field
    String protoField = m.group(6).trim();
    int dot = protoField.lastIndexOf('.');
    String appName = dot >= 0 ? protoField.substring(dot + 1) : protoField;
    if (SKIP_PROTOCOLS.contains(appName)) appName = null;
    if (appName != null && appName.length() > 50) appName = appName.substring(0, 50);

    // Risk names from [Risk: ** Name1 **** Name2 **] block
    List<String> risks = new ArrayList<>();
    Matcher rb = RISK_BLOCK.matcher(line);
    if (rb.find()) {
      Matcher rn = RISK_NAME.matcher(rb.group(1));
      while (rn.find()) {
        risks.add(normaliseRisk(rn.group(1)));
      }
    }

    // Traffic category from [cat: Name/ID] field
    String category = null;
    Matcher cm = CATEGORY.matcher(line);
    if (cm.find()) {
      category = cm.group(1).trim();
      if (category.length() > 50) category = category.substring(0, 50);
    }

    result.put(flowKey(srcIp, srcPort, dstIp, dstPort, l4proto), new FlowData(appName, risks, category));
  }

  /** Lookup flow data trying both directions (src→dst and dst→src). */
  private FlowData resolve(Map<String, FlowData> flowMap, PcapParserService.ConversationInfo conv) {
    String key1 = flowKey(conv.getSrcIp(), conv.getSrcPort(),
                          conv.getDstIp(), conv.getDstPort(), conv.getProtocol());
    FlowData data = flowMap.get(key1);
    if (data == null) {
      String key2 = flowKey(conv.getDstIp(), conv.getDstPort(),
                            conv.getSrcIp(), conv.getSrcPort(), conv.getProtocol());
      data = flowMap.get(key2);
    }
    return data;
  }

  /**
   * Normalise a raw nDPI risk label to lowercase-underscore form.
   * E.g. "Clear-Text Credentials" → "clear_text_credentials"
   *      "Known Protocol on Non Standard Port" → "known_protocol_on_non_standard_port"
   */
  private String normaliseRisk(String raw) {
    return raw.trim()
        .toLowerCase()
        .replaceAll("[^a-z0-9]+", "_")
        .replaceAll("^_|_$", "");
  }

  /** Remove surrounding IPv6 brackets: [fe80::1] → fe80::1 */
  private String stripBrackets(String ip) {
    if (ip != null && ip.startsWith("[") && ip.endsWith("]")) {
      return ip.substring(1, ip.length() - 1);
    }
    return ip;
  }

  private String flowKey(String ip, Integer port, String ip2, Integer port2, String proto) {
    return String.format("%s:%s->%s:%s/%s",
        ip, port, ip2, port2, proto != null ? proto.toUpperCase() : "");
  }

  private boolean isNotFoundError(Exception e) {
    String msg = e.getMessage();
    return msg != null && (msg.contains("No such file") || msg.contains("error=2"));
  }
}
