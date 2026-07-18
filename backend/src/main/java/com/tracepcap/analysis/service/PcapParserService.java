package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.PacketEntity;
import com.tracepcap.common.TsharkHexUtil;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/** Service for parsing PCAP/pcapng files using tshark. */
@Slf4j
@Service
public class PcapParserService {

  public PcapAnalysisResult analyzePcapFile(File pcapFile) {
    log.info("Starting PCAP analysis for file: {}", pcapFile.getName());

    PcapAnalysisResult result = new PcapAnalysisResult();
    result.setProtocolCounts(new HashMap<>());
    result.setProtocolBytes(new HashMap<>());
    result.setConversations(new ArrayList<>());
    // First-seen TTL and MAC per source IP (used for device classification)
    Map<String, Integer> hostTtls = new HashMap<>();
    Map<String, String> hostMacs = new HashMap<>();
    // All distinct source MACs seen per IP. Usually one; more than one within a single capture is
    // the tell for two devices sharing an IP (overlapping networks / ARP conflict) — #461.
    Map<String, LinkedHashSet<String>> hostMacObservations = new HashMap<>();

    Map<String, ConversationInfo> conversationMap = new HashMap<>();

    // Fields: epoch | len | ipv4.src | ipv4.dst | ipv6.src | ipv6.dst |
    //         tcp.sport | tcp.dport | udp.sport | udp.dport | protocol | info |
    //         tcp.payload | udp.payload | ip.ttl | eth.src |
    //         arp.src.proto_ipv4 | arp.dst.proto_ipv4 | eth.dst | arp.src.hw_mac |
    //         frame.number
    ProcessBuilder pb =
        new ProcessBuilder(
            "tshark",
            "-r",
            pcapFile.getAbsolutePath(),
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.len",
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
            "_ws.col.Protocol",
            "-e",
            "_ws.col.Info",
            "-e",
            "tcp.payload",
            "-e",
            "udp.payload",
            "-e",
            "ip.ttl",
            "-e",
            "eth.src",
            "-e",
            "arp.src.proto_ipv4",
            "-e",
            "arp.dst.proto_ipv4",
            "-e",
            "eth.dst",
            "-e",
            "arp.src.hw_mac",
            "-e",
            "frame.number",
            // Every field emitted AFTER _ws.col.Info is read from the END of the parsed row, not by
            // fixed index — see the parse loop. That is mandatory, not just convenient: _ws.col.Info
            // is free text that can contain the '|' separator, and a '|' there shifts every following
            // fixed index (once corrupted packet numbers, #496; later put payload hex into the ARP-IP
            // slot and overflowed a varchar(45) column, #550). Anything appended here stays safe as
            // long as it goes after Info and the TAIL count in the parse loop is kept in sync.
            "-e",
            "tcp.flags.syn",
            "-e",
            "tcp.flags.ack");
    pb.redirectErrorStream(false);

    // `packetNumber` counts parsed packets (used for packetCount); each packet's stored number is
    // the real tshark frame.number (read tail-relative in the parse loop) so other passes can locate
    // a packet by it.
    long packetNumber = 0;
    try {
      Process process = pb.start();

      // Drain stderr in a background thread so it doesn't block stdout
      StringBuffer stderrBuf = new StringBuffer();
      Thread stderrThread =
          new Thread(
              () -> {
                try (BufferedReader err =
                    new BufferedReader(
                        new InputStreamReader(
                            process.getErrorStream(), java.nio.charset.StandardCharsets.UTF_8))) {
                  String l;
                  while ((l = err.readLine()) != null) {
                    if (stderrBuf.length() < 10_000) stderrBuf.append(l).append('\n');
                  }
                } catch (Exception e) {
                  log.warn("Failed to drain tshark stderr", e);
                }
              });
      stderrThread.setDaemon(true);
      stderrThread.start();

      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null) {
          if (line.isEmpty()) continue;
          String[] f = line.split("\\|", -1);
          if (f.length < 11) continue;

          packetNumber++;
          double epochSec = f[0].isEmpty() ? 0 : Double.parseDouble(f[0]);
          int packetSize = f[1].isEmpty() ? 0 : Integer.parseInt(f[1]);

          // Prefer IPv4, fall back to IPv6.
          // tshark may return comma-separated values for tunneled/multi-layer packets — take first.
          String srcIp = firstValue(f[2].isEmpty() ? (f[4].isEmpty() ? null : f[4]) : f[2]);
          String dstIp = firstValue(f[3].isEmpty() ? (f[5].isEmpty() ? null : f[5]) : f[3]);
          // Truncate to varchar(45) limit
          if (srcIp != null && srcIp.length() > 45) srcIp = srcIp.substring(0, 45);
          if (dstIp != null && dstIp.length() > 45) dstIp = dstIp.substring(0, 45);

          String tcpSport = firstValue(f[6]);
          String tcpDport = firstValue(f[7]);
          String udpSport = firstValue(f[8]);
          String udpDport = firstValue(f[9]);
          String protocolRaw = f[10].isEmpty() ? "OTHER" : firstValue(f[10]).toUpperCase();
          String protocol = protocolRaw.length() > 20 ? protocolRaw.substring(0, 20) : protocolRaw;
          // Everything from _ws.col.Info (index 11) onward is read RELATIVE TO THE END of the row,
          // never by fixed index. _ws.col.Info is free text that can contain the '|' separator (FTP
          // passive-mode "(|||50076", multi-line SMTP/SIP/LDAP messages, ...). A '|' there splits
          // Info into extra columns and shifts every field after it. The post-Info fields are all
          // structured and fixed in count (TAIL of them), so anchoring them to the tail keeps them
          // aligned no matter how many '|' Info contains. Before this, a shifted tcp.payload hex
          // string landed in the arp.src.proto_ipv4 slot and overflowed ip_mac_observations.ip
          // (varchar(45)), aborting the whole analysis transaction. (#550)
          //
          // Tail layout, from the end: tcp.payload, udp.payload, ip.ttl, eth.src,
          // arp.src.proto_ipv4, arp.dst.proto_ipv4, eth.dst, arp.src.hw_mac, frame.number,
          // tcp.flags.syn, tcp.flags.ack.
          final int TAIL = 11; // structured fields emitted after _ws.col.Info
          final int n = f.length;
          // 11 head fields + Info (>=1 column) + TAIL fields. A shorter row is malformed/truncated;
          // treat its post-Info fields as absent rather than risk reading a head field as a tail one.
          boolean aligned = n >= 11 + 1 + TAIL;

          // Info spans the columns between the head and the tail; rejoin the pieces a '|' split apart.
          String info = protocol;
          if (aligned) {
            StringBuilder sb = new StringBuilder();
            for (int i = 11; i <= n - TAIL - 1; i++) {
              if (i > 11) sb.append('|');
              sb.append(f[i]);
            }
            if (sb.length() > 0) info = sb.toString();
          } else if (f.length > 11 && !f[11].isEmpty()) {
            info = f[11];
          }

          String tcpPayloadField = aligned ? f[n - 11] : "";
          String udpPayloadField = aligned ? f[n - 10] : "";

          // First-seen TTL for the source IP — best-effort, may be absent.
          Integer ttl = null;
          if (aligned && !f[n - 9].isEmpty()) {
            try {
              ttl = Integer.parseInt(firstValue(f[n - 9]));
            } catch (NumberFormatException ignored) {
            }
          }
          String srcMac = aligned && !f[n - 8].isEmpty() ? firstValue(f[n - 8]).toLowerCase() : null;

          // Layer-2 address fallback for non-IP protocols (ARP, STP, LLDP, CDP, etc.).
          // For ARP: use the embedded protocol (IP) addresses from the ARP payload.
          // For other pure L2 frames: use Ethernet MAC addresses as node identifiers.
          String arpSrcIp = aligned && !f[n - 7].isEmpty() ? firstValue(f[n - 7]) : null;
          String arpDstIp = aligned && !f[n - 6].isEmpty() ? firstValue(f[n - 6]) : null;
          String dstMac = aligned && !f[n - 5].isEmpty() ? firstValue(f[n - 5]).toLowerCase() : null;
          // ARP sender hardware address — the "I own this IP at this MAC" claim.
          String arpSrcMac = aligned && !f[n - 4].isEmpty() ? firstValue(f[n - 4]).toLowerCase() : null;
          // Belt-and-suspenders: these embedded IPs can become a node id and persist to a
          // varchar(45) column (e.g. ip_mac_observations.ip), so cap them like srcIp/dstIp above.
          if (arpSrcIp != null && arpSrcIp.length() > 45) arpSrcIp = arpSrcIp.substring(0, 45);
          if (arpDstIp != null && arpDstIp.length() > 45) arpDstIp = arpDstIp.substring(0, 45);
          if (srcIp == null) srcIp = (arpSrcIp != null) ? arpSrcIp : srcMac;
          if (dstIp == null) dstIp = (arpDstIp != null) ? arpDstIp : dstMac;

          LocalDateTime timestamp =
              LocalDateTime.ofInstant(
                  Instant.ofEpochMilli((long) (epochSec * 1000)), ZoneId.systemDefault());

          if (result.getStartTime() == null || timestamp.isBefore(result.getStartTime())) {
            result.setStartTime(timestamp);
          }
          if (result.getEndTime() == null || timestamp.isAfter(result.getEndTime())) {
            result.setEndTime(timestamp);
          }

          result.setTotalBytes(result.getTotalBytes() + packetSize);
          incrementProtocolCount(result, protocol, packetSize);

          // Record first-seen TTL and MAC for source IP
          if (srcIp != null) {
            if (ttl != null) hostTtls.putIfAbsent(srcIp, ttl);
            if (srcMac != null) hostMacs.putIfAbsent(srcIp, srcMac);
          }

          // Overlap detection (#461): record the IP↔MAC ownership claim from ARP
          // (arp.src.proto_ipv4 ↔ arp.src.hw_mac) — NOT the IP-layer eth.src. A routed host's
          // IP packets carry the gateway's MAC as eth.src, so keying off eth.src would falsely flag
          // every off-subnet server as "two MACs". ARP is the authoritative "who owns this IP"
          // statement, so two distinct hw_macs claiming one IP is a genuine same-segment conflict.
          if (arpSrcIp != null && arpSrcMac != null) {
            hostMacObservations
                .computeIfAbsent(arpSrcIp, k -> new LinkedHashSet<>())
                .add(arpSrcMac);
          }

          // Track conversations for IP traffic
          if (srcIp != null && dstIp != null) {
            Integer srcPort = null;
            Integer dstPort = null;

            if (!tcpSport.isEmpty()) {
              srcPort = Integer.parseInt(tcpSport);
              dstPort = Integer.parseInt(tcpDport);
            } else if (!udpSport.isEmpty()) {
              srcPort = Integer.parseInt(udpSport);
              dstPort = Integer.parseInt(udpDport);
            }

            final String fSrcIp = srcIp, fDstIp = dstIp;
            final Integer fSrcPort = srcPort, fDstPort = dstPort;
            final String fProtocol = protocol;
            final LocalDateTime fTs = timestamp;

            String convKey = createConversationKey(srcIp, srcPort, dstIp, dstPort, protocol);
            ConversationInfo conv =
                conversationMap.computeIfAbsent(
                    convKey,
                    k -> {
                      ConversationInfo c = new ConversationInfo();
                      c.setSrcIp(fSrcIp);
                      c.setSrcPort(fSrcPort);
                      c.setDstIp(fDstIp);
                      c.setDstPort(fDstPort);
                      c.setProtocol(fProtocol);
                      c.setStartTime(fTs);
                      c.setEndTime(fTs);
                      c.setPacketCount(0L);
                      c.setTotalBytes(0L);
                      return c;
                    });
            conv.setPacketCount(conv.getPacketCount() + 1);
            conv.setTotalBytes(conv.getTotalBytes() + packetSize);
            if (timestamp.isAfter(conv.getEndTime())) conv.setEndTime(timestamp);

            // Who opened this connection (#496). SYN without ACK is the opening packet; SYN+ACK is
            // the answer to it, so the ACK bit is what tells the two apart. The first one wins: a
            // retransmitted SYN must not flip the initiator, and it cannot legitimately change.
            //
            // Absent for UDP/ICMP/ARP, and for TCP flows the capture joined mid-stream. That stays
            // null. Falling back to "lower port wins" is exactly the guess this replaces — a server
            // on :4434 is a server, whatever its port number says.
            // SYN without ACK — the two trailing fields, read from the end for the same reason
            // frame.number is (an Info-column '|' must not shift them). Guarded on length so a row
            // that somehow lacks the flag columns skips this rather than indexing out of bounds.
            if (conv.getInitiatorIp() == null
                && f.length >= 3
                && "1".equals(f[f.length - 2])
                && !"1".equals(f[f.length - 1])) {
              conv.setInitiatorIp(fSrcIp);
              conv.setInitiatorPort(fSrcPort);
            }

            // Extract payload hex from tcp.payload / udp.payload (both read tail-relative above, for
            // the same reason as the other post-Info fields — a '|' in Info must not shift them).
            // tshark outputs byte arrays as colon-separated hex pairs (e.g. "48:54:54:50").
            String tsharkPayload = null;
            if (!tcpPayloadField.isEmpty()) {
              tsharkPayload = tcpPayloadField; // tcp.payload
            } else if (!udpPayloadField.isEmpty()) {
              tsharkPayload = udpPayloadField; // udp.payload
            }
            String payloadHex = TsharkHexUtil.toHex(tsharkPayload, PacketEntity.PAYLOAD_BYTE_LIMIT);
            // The three trailing fields, in order, are frame.number, tcp.flags.syn, tcp.flags.ack.
            // Read them from the END, not by fixed index: a '|' inside an earlier column (Info) would
            // shift every fixed index, and appending syn/ack already moved frame.number off the last
            // slot once — reading from the tail is what keeps that from silently corrupting data.
            long frameNumber = packetNumber;
            String rawFrame = f.length >= 3 ? f[f.length - 3] : null;
            if (rawFrame != null && !rawFrame.isEmpty()) {
              try {
                frameNumber = Long.parseLong(rawFrame.trim());
              } catch (NumberFormatException ignored) {
                // keep counter fallback
              }
            }
            conv.getPackets()
                .add(
                    buildPacketInfo(
                        frameNumber,
                        timestamp,
                        srcIp,
                        srcPort,
                        dstIp,
                        dstPort,
                        protocol,
                        packetSize,
                        info,
                        payloadHex));
          }
        }
      }

      stderrThread.join(5000);
      int exitCode = process.waitFor();
      if (exitCode != 0 && packetNumber == 0) {
        String stderr = stderrBuf.toString().trim();
        log.error("tshark exited with code {} and parsed 0 packets. stderr: {}", exitCode, stderr);
        throw new RuntimeException(
            "tshark failed to parse PCAP file (exit " + exitCode + "): " + stderr);
      }

    } catch (RuntimeException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException("tshark parsing failed: " + e.getMessage(), e);
    }

    result.setPacketCount(packetNumber);
    result.setConversations(new ArrayList<>(conversationMap.values()));
    result.setHostTtls(hostTtls);
    result.setHostMacs(hostMacs);
    result.setHostMacObservations(hostMacObservations);

    log.info(
        "PCAP analysis completed: {} packets, {} bytes, {} conversations",
        result.getPacketCount(),
        result.getTotalBytes(),
        result.getConversations().size());

    return result;
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private PacketInfo buildPacketInfo(
      long packetNumber,
      LocalDateTime timestamp,
      String srcIp,
      Integer srcPort,
      String dstIp,
      Integer dstPort,
      String protocol,
      int packetSize,
      String info,
      String payloadHex) {

    PacketInfo pkt = new PacketInfo();
    pkt.setPacketNumber(packetNumber);
    pkt.setTimestamp(timestamp);
    pkt.setSrcIp(srcIp);
    pkt.setSrcPort(srcPort);
    pkt.setDstIp(dstIp);
    pkt.setDstPort(dstPort);
    pkt.setProtocol(protocol);
    pkt.setPacketSize(packetSize);
    pkt.setInfo(info);
    pkt.setPayload(payloadHex);
    pkt.setDetectedFileType(FileSignatureDetector.detect(TsharkHexUtil.toBytes(payloadHex)));
    return pkt;
  }

  /** Return the first comma-separated value, or the original string if no comma. */
  private String firstValue(String s) {
    if (s == null || s.isEmpty()) return s;
    int comma = s.indexOf(',');
    return comma < 0 ? s : s.substring(0, comma);
  }

  private void incrementProtocolCount(PcapAnalysisResult result, String protocol, int packetSize) {
    result.getProtocolCounts().merge(protocol, 1L, Long::sum);
    result.getProtocolBytes().merge(protocol, (long) packetSize, Long::sum);
  }

  private String createConversationKey(
      String srcIp, Integer srcPort, String dstIp, Integer dstPort, String protocol) {
    String ip1, ip2;
    Integer port1, port2;

    int cmp = srcIp.compareTo(dstIp);
    if (cmp < 0 || (cmp == 0 && srcPort != null && dstPort != null && srcPort < dstPort)) {
      ip1 = srcIp;
      port1 = srcPort;
      ip2 = dstIp;
      port2 = dstPort;
    } else {
      ip1 = dstIp;
      port1 = dstPort;
      ip2 = srcIp;
      port2 = srcPort;
    }
    return String.format("%s:%s-%s:%s-%s", ip1, port1, ip2, port2, protocol);
  }

  // ---------------------------------------------------------------------------
  // Result classes
  // ---------------------------------------------------------------------------

  @lombok.Data
  public static class PcapAnalysisResult {
    private Long packetCount = 0L;
    private Long totalBytes = 0L;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private Map<String, Long> protocolCounts;
    private Map<String, Long> protocolBytes;
    private List<ConversationInfo> conversations;

    /** First-seen TTL value per source IP address. */
    private Map<String, Integer> hostTtls = new HashMap<>();

    /** First-seen Ethernet source MAC address per source IP address. */
    private Map<String, String> hostMacs = new HashMap<>();

    /** All distinct source MACs seen per source IP (>1 ⇒ possible overlapping networks, #461). */
    private Map<String, LinkedHashSet<String>> hostMacObservations = new HashMap<>();
  }

  @lombok.Data
  public static class ConversationInfo {
    private String srcIp;
    private Integer srcPort;
    private String dstIp;
    private Integer dstPort;

    /**
     * The endpoint that opened the connection — the one that sent SYN without ACK (#496).
     *
     * <p><b>Not the same as {@link #srcIp}.</b> Conversation keys are normalised so that A→B and
     * B→A share one bucket, which means srcIp is "whichever endpoint sorted first", not "who
     * started it". Direction used to be lost entirely at this point, which is why the frontend
     * resorted to guessing a host's role from port numbers — and why a server on a high port
     * (:4434) was called a client.
     *
     * <p><b>Null means unknown, never "nobody initiated".</b> UDP, ICMP and ARP have no handshake;
     * a capture can also begin mid-flow and miss the SYN. Guessing from ports to fill the gap is
     * the bug, not the fallback.
     */
    private String initiatorIp;

    private Integer initiatorPort;
    private String protocol;
    private String appName;
    private String tsharkProtocol;
    private List<String> flowRisks = new ArrayList<>();
    private List<String> customSignatures = new ArrayList<>();
    private List<String> suricataAlerts = new ArrayList<>();
    private List<String> httpUserAgents = new ArrayList<>();
    private String category;
    private String hostname;
    private String ja3Client;
    private String ja3Server;
    private String tlsIssuer;
    private String tlsSubject;
    private LocalDateTime tlsNotBefore;
    private LocalDateTime tlsNotAfter;
    private Long packetCount;
    private Long totalBytes;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private List<PacketInfo> packets = new ArrayList<>();
  }

  @lombok.Data
  public static class PacketInfo {
    private Long packetNumber;
    private LocalDateTime timestamp;
    private String srcIp;
    private Integer srcPort;
    private String dstIp;
    private Integer dstPort;
    private String protocol;
    private Integer packetSize;
    private String info;

    /** First {@link PacketEntity#PAYLOAD_BYTE_LIMIT} bytes as a lowercase hex string, or null. */
    private String payload;

    /** File type detected from magic bytes, or null if unknown. */
    private String detectedFileType;
  }
}
