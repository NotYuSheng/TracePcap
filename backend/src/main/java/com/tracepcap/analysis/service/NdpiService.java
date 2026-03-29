package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.ConversationEntity;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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
   *
   * <p>The l4proto group now accepts any word token (not just TCP/UDP) so that non-TCP/UDP
   * protocols such as IGMP, GRE, OSPF, SCTP are also captured.
   * For non-TCP/UDP flows ndpiReader emits port 0; those are treated as null (no port).
   */
  private static final Pattern FLOW_LINE = Pattern.compile(
      "\\t\\d+\\t(\\w+)\\s+" +
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

  /** Matches the hostname/SNI field, e.g. [Hostname/SNI: zoom.us] → group(1) = "zoom.us". */
  private static final Pattern HOSTNAME = Pattern.compile(
      "\\[Hostname/SNI:\\s*([^\\]]+)\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** Matches the JA3 client fingerprint, e.g. [JA3C: abcdef...] → group(1) = hash. */
  private static final Pattern JA3C = Pattern.compile(
      "\\[JA3C:\\s*([0-9a-f]{" + ConversationEntity.JA3_HASH_LENGTH + "})\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** Matches the JA3S server fingerprint, e.g. [JA3S: abcdef...] → group(1) = hash. */
  private static final Pattern JA3S = Pattern.compile(
      "\\[JA3S:\\s*([0-9a-f]{" + ConversationEntity.JA3_HASH_LENGTH + "})\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** Matches TLS certificate issuer DN, e.g. [Issuer: CN=...] → group(1) = DN string. */
  private static final Pattern TLS_ISSUER = Pattern.compile(
      "\\[Issuer:\\s*([^\\]]+)\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** Matches TLS certificate subject DN, e.g. [Subject: CN=...] → group(1) = DN string. */
  private static final Pattern TLS_SUBJECT = Pattern.compile(
      "\\[Subject:\\s*([^\\]]+)\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** Matches TLS certificate not-before date, e.g. [NotBefore: 2020/01/01 00:00:00] → group(1). */
  private static final Pattern TLS_NOT_BEFORE = Pattern.compile(
      "\\[NotBefore:\\s*([^\\]]+)\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** Matches TLS certificate not-after date, e.g. [NotAfter: 2021/01/01 00:00:00] → group(1). */
  private static final Pattern TLS_NOT_AFTER = Pattern.compile(
      "\\[NotAfter:\\s*([^\\]]+)\\]",
      Pattern.CASE_INSENSITIVE
  );

  /** nDPI prints TLS validity dates as {@code yyyy/MM/dd HH:mm:ss} (UTC). */
  private static final DateTimeFormatter NDPI_DATE_FMT =
      DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");

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
      // Store nDPI's detection in ndpiProtocol; appName is resolved later by TsharkEnrichmentService
      // (tshark wins; nDPI is the fallback when tshark cannot identify the flow)
      if (data.appName() != null) conv.setNdpiProtocol(correctMisclassification(data.appName(), conv.getSrcPort(), conv.getDstPort(), conv.getProtocol()));
      if (!data.risks().isEmpty()) conv.setFlowRisks(data.risks());
      if (data.category() != null) conv.setCategory(data.category());
      if (data.hostname() != null) conv.setHostname(data.hostname());
      if (data.ja3Client() != null) conv.setJa3Client(data.ja3Client());
      if (data.ja3Server() != null) conv.setJa3Server(data.ja3Server());
      if (data.tlsIssuer() != null) conv.setTlsIssuer(data.tlsIssuer());
      if (data.tlsSubject() != null) conv.setTlsSubject(data.tlsSubject());
      if (data.tlsNotBefore() != null) conv.setTlsNotBefore(data.tlsNotBefore());
      if (data.tlsNotAfter() != null) conv.setTlsNotAfter(data.tlsNotAfter());
    }

    long enrichedApps       = conversations.stream().filter(c -> c.getNdpiProtocol() != null).count();
    long enrichedRisks      = conversations.stream().filter(c -> !c.getFlowRisks().isEmpty()).count();
    long enrichedCategories = conversations.stream().filter(c -> c.getCategory() != null).count();
    long enrichedHostnames  = conversations.stream().filter(c -> c.getHostname() != null).count();
    long enrichedJa3        = conversations.stream().filter(c -> c.getJa3Client() != null).count();
    long enrichedTlsCert    = conversations.stream().filter(c -> c.getTlsIssuer() != null).count();
    log.info("nDPI identified protocols: {}/{}, risks: {}/{}, categories: {}/{}, hostnames: {}/{}, JA3: {}/{}, TLS certs: {}/{}",
        enrichedApps, conversations.size(), enrichedRisks, conversations.size(),
        enrichedCategories, conversations.size(), enrichedHostnames, conversations.size(),
        enrichedJa3, conversations.size(), enrichedTlsCert, conversations.size());
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  /** Immutable holder for per-flow nDPI data extracted from one -v 2 line. */
  private record FlowData(String appName, List<String> risks, String category, String hostname,
                          String ja3Client, String ja3Server,
                          String tlsIssuer, String tlsSubject,
                          LocalDateTime tlsNotBefore, LocalDateTime tlsNotAfter) {}

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

    String l4proto    = m.group(1).toUpperCase();
    String srcIp      = stripBrackets(m.group(2));
    int    srcPortInt = Integer.parseInt(m.group(3));
    String dstIp      = stripBrackets(m.group(4));
    int    dstPortInt = Integer.parseInt(m.group(5));
    // Non-TCP/UDP protocols (e.g. IGMP, PIM, GRE) have no ports; ndpiReader emits 0.
    boolean isTcpUdp  = "TCP".equals(l4proto) || "UDP".equals(l4proto);
    Integer srcPort   = (!isTcpUdp && srcPortInt == 0) ? null : srcPortInt;
    Integer dstPort   = (!isTcpUdp && dstPortInt == 0) ? null : dstPortInt;

    // App name from proto field
    String protoField = m.group(6).trim();
    int dot = protoField.lastIndexOf('.');
    String appName = dot >= 0 ? protoField.substring(dot + 1) : protoField;
    if (SKIP_PROTOCOLS.contains(appName)) appName = null;
    if (appName != null && appName.length() > ConversationEntity.APP_NAME_MAX_LENGTH)
      appName = appName.substring(0, ConversationEntity.APP_NAME_MAX_LENGTH);

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
      if (category.length() > ConversationEntity.CATEGORY_MAX_LENGTH)
        category = category.substring(0, ConversationEntity.CATEGORY_MAX_LENGTH);
    }

    // Hostname/SNI from [Hostname/SNI: host] field
    String hostname = null;
    Matcher hm = HOSTNAME.matcher(line);
    if (hm.find()) {
      hostname = hm.group(1).trim();
      if (hostname.length() > ConversationEntity.HOSTNAME_MAX_LENGTH)
        hostname = hostname.substring(0, ConversationEntity.HOSTNAME_MAX_LENGTH);
    }

    // JA3 client/server fingerprint hashes
    String ja3Client = extractHash(JA3C, line);
    String ja3Server = extractHash(JA3S, line);

    // TLS certificate metadata
    String tlsIssuer = extractText(TLS_ISSUER, line);
    String tlsSubject = extractText(TLS_SUBJECT, line);
    LocalDateTime tlsNotBefore = parseTlsDate(extractText(TLS_NOT_BEFORE, line));
    LocalDateTime tlsNotAfter  = parseTlsDate(extractText(TLS_NOT_AFTER, line));

    FlowData data = new FlowData(appName, risks, category, hostname, ja3Client, ja3Server,
                                 tlsIssuer, tlsSubject, tlsNotBefore, tlsNotAfter);
    result.put(flowKey(srcIp, srcPort, dstIp, dstPort, l4proto), data);
    // Also index portless flows by IP pair so resolve() can find them even when the l4proto
    // name used by ndpiReader (e.g. "IGMP") differs from pcap4j's IpNumber name (e.g. "IGMP").
    if (srcPort == null) {
      result.putIfAbsent(ipPairKey(srcIp, dstIp), data);
    }
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
    // IP-pair fallback for portless protocols (IGMP, PIM, GRE, OSPF…) where the l4proto
    // string from ndpiReader may differ from pcap4j's IpNumber name.
    if (data == null && conv.getSrcPort() == null && conv.getDstPort() == null) {
      data = flowMap.get(ipPairKey(conv.getSrcIp(), conv.getDstIp()));
    }
    return data;
  }

  /** Extract and lowercase a single captured group from a pattern match, or return null. */
  private String extractHash(Pattern pattern, String line) {
    Matcher m = pattern.matcher(line);
    return m.find() ? m.group(1).toLowerCase() : null;
  }

  /** Extract and trim a single captured group from a pattern match, or return null. */
  private String extractText(Pattern pattern, String line) {
    Matcher m = pattern.matcher(line);
    return m.find() ? m.group(1).trim() : null;
  }

  /** Parse a TLS validity date string (e.g. {@code 2020/01/01 00:00:00}) to LocalDateTime. */
  private LocalDateTime parseTlsDate(String raw) {
    if (raw == null) return null;
    try {
      return LocalDateTime.parse(raw, NDPI_DATE_FMT);
    } catch (java.time.format.DateTimeParseException e) {
      log.debug("Could not parse TLS date '{}': {}", raw, e.getMessage());
      return null;
    }
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

  /**
   * Canonical key for portless flows keyed only by IP pair (direction-independent).
   * Used as a fallback when the l4proto name in ndpiReader output differs from pcap4j's name.
   */
  private String ipPairKey(String ip1, String ip2) {
    return ip1.compareTo(ip2) <= 0
        ? "IPPAIR:" + ip1 + "<->" + ip2
        : "IPPAIR:" + ip2 + "<->" + ip1;
  }

  private String flowKey(String ip, Integer port, String ip2, Integer port2, String proto) {
    return String.format("%s:%s->%s:%s/%s",
        ip, port, ip2, port2, proto != null ? proto.toUpperCase() : "");
  }


  // Port constants for IANA-registered protocol assignments used in misclassification corrections
  private static final int PORT_UFTP  = 1044; // IANA: UDP — UFTP (Unicast File Transfer Protocol)
  private static final int PORT_H225  = 1720; // IANA: TCP — H.225 call signaling

  /**
   * Corrects known nDPI misclassifications using port and transport-layer heuristics.
   *
   * <p>Known cases:
   * <ul>
   *   <li>UFTP (UDP port 1044, IANA-registered) misclassified as BitTorrent — binary file-transfer
   *       payload triggers BitTorrent DPI heuristics in nDPI 5.0.0</li>
   *   <li>H.225/H.245 (TCP port 1720) misclassified as Cassandra — belt-and-suspenders guard
   *       for older nDPI builds where this is not yet fixed natively</li>
   *   <li>nDPI reports all H.323 suite flows as "H323" without distinguishing sub-protocols:
   *       <ul>
   *         <li>H.225 call signaling always uses TCP port 1720 (IANA-registered)</li>
   *         <li>H.245 media control always uses dynamically negotiated TCP ports</li>
   *       </ul>
   *       H.323 RAS (UDP port 1719, gatekeeper) is left as-is.</li>
   * </ul>
   */
  private static String correctMisclassification(String appName, Integer srcPort, Integer dstPort, String transport) {
    boolean isTcp = "TCP".equalsIgnoreCase(transport);
    boolean isUdp = "UDP".equalsIgnoreCase(transport);
    boolean onPort1044 = Integer.valueOf(PORT_UFTP).equals(srcPort) || Integer.valueOf(PORT_UFTP).equals(dstPort);
    boolean onPort1720 = Integer.valueOf(PORT_H225).equals(srcPort) || Integer.valueOf(PORT_H225).equals(dstPort);
    if ("BitTorrent".equalsIgnoreCase(appName) && isUdp && onPort1044) return "UFTP";
    if ("Cassandra".equalsIgnoreCase(appName)  && isTcp && onPort1720) return "H225";
    if ("H323".equalsIgnoreCase(appName)       && isTcp && onPort1720) return "H225";
    if ("H323".equalsIgnoreCase(appName)       && isTcp)               return "H245";
    return appName;
  }

  private boolean isNotFoundError(Exception e) {
    String msg = e.getMessage();
    return msg != null && (msg.contains("No such file") || msg.contains("error=2"));
  }
}
