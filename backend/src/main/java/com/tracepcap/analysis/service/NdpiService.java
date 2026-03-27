package com.tracepcap.analysis.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
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
 * Telegram) for each conversation in a PCAP file.
 *
 * <p>Uses: {@code ndpiReader -i <file> -v 2}
 *
 * <p>Per-flow lines (from -v 2) look like:
 *
 * <pre>
 *   \t1\tUDP 192.168.1.77:28150 <-> 91.108.8.1:533  [proto: 185/Telegram][Encrypted]...
 *   \t8\tUDP 10.0.0.1:443      <-> 1.2.3.4:1234    [proto: 188.126/QUIC.Google]...
 *   \t3\tUDP [fe80::1]:5353    ->  [ff02::fb]:5353  [proto: 8/MDNS]...
 * </pre>
 *
 * <p>The app name is extracted from the proto field: {@code N/Name} or {@code N.N/Master.App}. When
 * a dot is present in the name part (e.g. {@code QUIC.Google}), the part after the last dot is used
 * ({@code Google}).
 *
 * <p>Gracefully degrades: if ndpiReader is not available or fails, all appName fields remain null
 * and analysis continues normally.
 */
@Slf4j
@Service
public class NdpiService {

  private static final String NDPI_BINARY = "ndpiReader";

  /**
   * Matches per-flow lines from {@code ndpiReader -v 2}. Groups: (1) l4proto (2) srcIp (3) srcPort
   * (4) dstIp (5) dstPort (6) protoField
   *
   * <p>Handles IPv4 (192.168.1.1) and IPv6 ([fe80::1]) addresses, and both bidirectional (<->) and
   * unidirectional (->) flows.
   */
  private static final Pattern FLOW_LINE =
      Pattern.compile(
          "\\t\\d+\\t(TCP|UDP)\\s+"
              + "(\\[?[\\w:.]+]?):(\\d+)\\s+(?:<->|->)\\s+(\\[?[\\w:.]+]?):(\\d+)"
              + ".*?\\[proto:\\s*[\\d.]+/([^\\]]+)\\]",
          Pattern.CASE_INSENSITIVE);

  /** Transport-only names that carry no application-layer signal. */
  private static final Set<String> SKIP_PROTOCOLS =
      Set.of("TCP", "UDP", "ICMP", "ICMPv6", "Unknown", "UNKNOWN");

  /**
   * Enrich each ConversationInfo with the app name detected by nDPI. Conversations nDPI cannot
   * identify are left with appName == null.
   */
  public void enrichWithAppNames(
      File pcapFile, List<PcapParserService.ConversationInfo> conversations) {
    if (conversations.isEmpty()) return;

    Map<String, String> flowToApp = runNdpi(pcapFile);
    if (flowToApp.isEmpty()) return;

    for (PcapParserService.ConversationInfo conv : conversations) {
      String key1 =
          flowKey(
              conv.getSrcIp(),
              conv.getSrcPort(),
              conv.getDstIp(),
              conv.getDstPort(),
              conv.getProtocol());
      String key2 =
          flowKey(
              conv.getDstIp(),
              conv.getDstPort(),
              conv.getSrcIp(),
              conv.getSrcPort(),
              conv.getProtocol());
      String app = flowToApp.get(key1);
      if (app == null) app = flowToApp.get(key2);
      if (app != null) conv.setAppName(app);
    }

    long enriched = conversations.stream().filter(c -> c.getAppName() != null).count();
    log.info("nDPI enriched {}/{} conversations with app names", enriched, conversations.size());
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  private Map<String, String> runNdpi(File pcapFile) {
    Map<String, String> result = new HashMap<>();

    // -v 2 emits one line per flow with the 5-tuple and detected protocol
    ProcessBuilder pb =
        new ProcessBuilder(NDPI_BINARY, "-i", pcapFile.getAbsolutePath(), "-v", "2");

    try {
      Process process = pb.start();

      // Drain stderr on a background thread to avoid blocking stdout reading;
      // log at DEBUG so diagnostics are available without polluting normal logs.
      Thread stderrDrainer =
          new Thread(
              () -> {
                try (BufferedReader err =
                    new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                  String line;
                  while ((line = err.readLine()) != null) {
                    log.debug("ndpiReader stderr: {}", line);
                  }
                } catch (Exception ignored) {
                }
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
      log.debug("nDPI identified {} distinct flows", result.size());

    } catch (Exception e) {
      if (isNotFoundError(e)) {
        log.warn(
            "ndpiReader not found — skipping app identification. Install libndpi-bin to enable.");
      } else {
        log.warn("nDPI analysis failed", e);
      }
    }

    return result;
  }

  /**
   * Parse one ndpiReader -v 2 flow line into the result map.
   *
   * <p>Proto field examples: "Telegram" → Telegram "QUIC.Google" → Google (take after last dot)
   * "TLS.Zoom" → Zoom "MDNS" → MDNS
   */
  private void parseFlowLine(String line, Map<String, String> result) {
    Matcher m = FLOW_LINE.matcher(line);
    if (!m.find()) return;

    String l4proto = m.group(1).toUpperCase();
    String srcIp = stripBrackets(m.group(2));
    int srcPort = Integer.parseInt(m.group(3));
    String dstIp = stripBrackets(m.group(4));
    int dstPort = Integer.parseInt(m.group(5));

    // Extract app name from proto field, e.g. "QUIC.Google" → "Google"
    String protoField = m.group(6).trim();
    int dot = protoField.lastIndexOf('.');
    String appName = dot >= 0 ? protoField.substring(dot + 1) : protoField;

    if (SKIP_PROTOCOLS.contains(appName)) return;
    if (appName.length() > 50) appName = appName.substring(0, 50);

    result.put(flowKey(srcIp, srcPort, dstIp, dstPort, l4proto), appName);
  }

  /** Remove surrounding IPv6 brackets: [fe80::1] → fe80::1 */
  private String stripBrackets(String ip) {
    if (ip != null && ip.startsWith("[") && ip.endsWith("]")) {
      return ip.substring(1, ip.length() - 1);
    }
    return ip;
  }

  private String flowKey(String ip, Integer port, String ip2, Integer port2, String proto) {
    return String.format(
        "%s:%s->%s:%s/%s", ip, port, ip2, port2, proto != null ? proto.toUpperCase() : "");
  }

  private boolean isNotFoundError(Exception e) {
    String msg = e.getMessage();
    return msg != null && (msg.contains("No such file") || msg.contains("error=2"));
  }
}
