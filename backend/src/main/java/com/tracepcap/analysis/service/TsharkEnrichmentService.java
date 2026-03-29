package com.tracepcap.analysis.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Runs tshark as a subprocess to obtain Wireshark's dissector-based protocol label for each
 * conversation, stored in {@code tsharkProtocol}. Complements nDPI's application identification.
 *
 * <p>Uses: {@code tshark -r <file> -T fields -e ip.src -e ip.dst ... -e _ws.col.Protocol}
 *
 * <p>Responsibility split:
 *
 * <ul>
 *   <li>nDPI ({@link NdpiService}) — sets {@code appName} and {@code category} (application-layer
 *       identification, e.g. "YouTube", "WhatsApp")
 *   <li>tshark (this service) — sets {@code tsharkProtocol} only (protocol-layer label, e.g. "TLS",
 *       "HTTP", "QUIC")
 * </ul>
 *
 * <p>Both values are shown in the UI as complementary information.
 *
 * <p>Gracefully degrades: if tshark is not available, all {@code tsharkProtocol} fields remain null
 * and analysis continues normally.
 */
@Slf4j
@Service
public class TsharkEnrichmentService {

  private static final String TSHARK_BINARY = "tshark";

  /**
   * Transport / link-layer protocol names that carry no application-layer signal. When a flow's
   * packets only produce these labels we still record the most common one as tsharkProtocol, but we
   * do not promote it to appName if nDPI already has a value.
   */
  private static final Set<String> TRANSPORT_LAYER =
      Set.of(
          "TCP",
          "UDP",
          "ICMP",
          "ICMPV6",
          "GRE",
          "ESP",
          "AH",
          "SCTP",
          "OSPF",
          "PIM",
          "VRRP",
          "IGMP",
          "IGMPV2",
          "IGMPV3",
          "ETHERNET",
          "ETH",
          "ARP",
          "IPV4",
          "IPV6",
          "VLAN",
          "LLC",
          "STP",
          "RSTP",
          "CDP",
          "LLDP",
          "SLL",
          "DATA",
          "FRAME",
          "RAW");

  /** ip.proto number → transport protocol name. */
  private static final Map<String, String> IP_PROTO =
      Map.ofEntries(
          Map.entry("1", "ICMP"),
          Map.entry("2", "IGMP"),
          Map.entry("6", "TCP"),
          Map.entry("17", "UDP"),
          Map.entry("47", "GRE"),
          Map.entry("50", "ESP"),
          Map.entry("51", "AH"),
          Map.entry("58", "ICMPv6"),
          Map.entry("89", "OSPF"),
          Map.entry("103", "PIM"),
          Map.entry("112", "VRRP"),
          Map.entry("132", "SCTP"));

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Enriches each conversation with Wireshark's dissector-based protocol label, stored in {@code
   * tsharkProtocol}. Does not modify {@code appName} — that is owned by nDPI.
   */
  public void enrich(File pcapFile, List<PcapParserService.ConversationInfo> conversations) {
    if (conversations.isEmpty()) return;

    Map<String, Map<String, Integer>> flowFreq = new HashMap<>();
    Map<String, Map<String, Integer>> ipPairFreq = new HashMap<>();

    runTshark(pcapFile, flowFreq, ipPairFreq);

    int enriched = 0;
    for (PcapParserService.ConversationInfo conv : conversations) {
      Map<String, Integer> freq = lookupFreq(conv, flowFreq, ipPairFreq);
      String detected = (freq != null) ? selectBestProtocol(freq) : null;
      if (detected != null) {
        conv.setTsharkProtocol(detected);
        enriched++;
      }
    }
    log.info(
        "tshark enrichment: set tsharkProtocol on {}/{} conversations",
        enriched,
        conversations.size());
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  private void runTshark(
      File pcapFile,
      Map<String, Map<String, Integer>> flowFreq,
      Map<String, Map<String, Integer>> ipPairFreq) {
    ProcessBuilder pb =
        new ProcessBuilder(
            TSHARK_BINARY,
            "-r",
            pcapFile.getAbsolutePath(),
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "ip.proto",
            "-e",
            "ipv6.nxt",
            "-e",
            "_ws.col.Protocol");
    pb.redirectErrorStream(false);

    try {
      Process process = pb.start();

      // Drain stderr in background to prevent blocking
      Thread errDrainer =
          new Thread(
              () -> {
                try (BufferedReader err =
                    new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                  String line;
                  while ((line = err.readLine()) != null) log.debug("tshark stderr: {}", line);
                } catch (Exception e) {
                  log.debug("Error draining tshark stderr", e);
                }
              });
      errDrainer.setDaemon(true);
      errDrainer.start();

      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null) {
          parseLine(line, flowFreq, ipPairFreq);
        }
      }
      process.waitFor();
      log.debug("tshark protocol scan complete: {} distinct flow keys", flowFreq.size());

    } catch (Exception e) {
      if (isNotFound(e)) {
        log.warn("tshark not found — skipping Wireshark protocol enrichment.");
      } else {
        log.warn("tshark protocol enrichment failed: {}", e.getMessage());
      }
    }
  }

  /**
   * Parse one tshark tab-separated output line into the frequency maps.
   *
   * <p>Field order matches the {@code -e} arguments above (0-indexed): 0=ip.src, 1=ip.dst,
   * 2=ipv6.src, 3=ipv6.dst, 4=tcp.srcport, 5=tcp.dstport, 6=udp.srcport, 7=udp.dstport, 8=ip.proto,
   * 9=ipv6.nxt, 10=_ws.col.Protocol
   */
  private void parseLine(
      String line,
      Map<String, Map<String, Integer>> flowFreq,
      Map<String, Map<String, Integer>> ipPairFreq) {
    String[] f = line.split("\t", -1);
    if (f.length < 11) return;

    // Resolve IP (prefer v4, fall back to v6)
    String srcIp = !f[0].isEmpty() ? f[0] : (!f[2].isEmpty() ? f[2] : null);
    String dstIp = !f[1].isEmpty() ? f[1] : (!f[3].isEmpty() ? f[3] : null);
    if (srcIp == null || dstIp == null) return;

    // Ports — TCP fields take precedence over UDP
    Integer srcPort = parsePort(!f[4].isEmpty() ? f[4] : f[6]);
    Integer dstPort = parsePort(!f[5].isEmpty() ? f[5] : f[7]);

    // Transport protocol from ip.proto / ipv6.nxt number
    String protoNum = !f[8].isEmpty() ? f[8] : f[9];
    String proto =
        IP_PROTO.getOrDefault(protoNum, protoNum.isEmpty() ? "UNKNOWN" : protoNum.toUpperCase());

    String displayProto = f[10].trim();
    if (displayProto.isEmpty()) return;

    // Use a canonical (direction-independent) key so both A→B and B→A packets merge
    String key = canonicalKey(srcIp, srcPort, dstIp, dstPort, proto);
    flowFreq.computeIfAbsent(key, k -> new HashMap<>()).merge(displayProto, 1, Integer::sum);

    // Portless fallback (ICMP, OSPF, GRE, etc.)
    if (srcPort == null && dstPort == null) {
      ipPairFreq
          .computeIfAbsent(ipPairKey(srcIp, dstIp), k -> new HashMap<>())
          .merge(displayProto, 1, Integer::sum);
    }
  }

  private Map<String, Integer> lookupFreq(
      PcapParserService.ConversationInfo conv,
      Map<String, Map<String, Integer>> flowFreq,
      Map<String, Map<String, Integer>> ipPairFreq) {
    String key =
        canonicalKey(
            conv.getSrcIp(),
            conv.getSrcPort(),
            conv.getDstIp(),
            conv.getDstPort(),
            conv.getProtocol());
    Map<String, Integer> freq = flowFreq.get(key);
    if (freq == null && conv.getSrcPort() == null && conv.getDstPort() == null) {
      freq = ipPairFreq.get(ipPairKey(conv.getSrcIp(), conv.getDstIp()));
    }
    return freq;
  }

  /**
   * Returns the most frequently seen application-layer protocol in the map. If all entries are
   * transport/link-layer names, returns the most common one instead.
   */
  private String selectBestProtocol(Map<String, Integer> freq) {
    // Prefer anything that isn't a bare transport/link-layer name
    String appLevel =
        freq.entrySet().stream()
            .filter(e -> !TRANSPORT_LAYER.contains(e.getKey().toUpperCase()))
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse(null);
    if (appLevel != null) return appLevel;
    // All generic — still store the most common transport name
    return freq.entrySet().stream()
        .max(Map.Entry.comparingByValue())
        .map(Map.Entry::getKey)
        .orElse(null);
  }

  /**
   * Direction-independent flow key: the endpoint with the lexicographically smaller IP goes first;
   * ties are broken by port number. This merges A→B and B→A packets into a single bucket.
   */
  private String canonicalKey(String ip1, Integer port1, String ip2, Integer port2, String proto) {
    int cmp = ip1.compareTo(ip2);
    if (cmp == 0) {
      // Null-safe port comparison: treat null as smaller than any valid port number.
      cmp = Integer.compare(port1 == null ? -1 : port1, port2 == null ? -1 : port2);
    }
    boolean swap = cmp > 0;
    return swap ? flowKey(ip2, port2, ip1, port1, proto) : flowKey(ip1, port1, ip2, port2, proto);
  }

  private String flowKey(String ip, Integer port, String ip2, Integer port2, String proto) {
    return String.format(
        "%s:%s->%s:%s/%s", ip, port, ip2, port2, proto != null ? proto.toUpperCase() : "");
  }

  private String ipPairKey(String ip1, String ip2) {
    return ip1.compareTo(ip2) <= 0 ? "IPPAIR:" + ip1 + "<->" + ip2 : "IPPAIR:" + ip2 + "<->" + ip1;
  }

  private Integer parsePort(String s) {
    if (s == null || s.isEmpty()) return null;
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException e) {
      return null;
    }
  }

  private boolean isNotFound(Exception e) {
    String msg = e.getMessage();
    return msg != null && (msg.contains("No such file") || msg.contains("error=2"));
  }
}
