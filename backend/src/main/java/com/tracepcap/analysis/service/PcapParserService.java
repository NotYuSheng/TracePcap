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

    Map<String, ConversationInfo> conversationMap = new HashMap<>();

    // Fields: epoch | len | ipv4.src | ipv4.dst | ipv6.src | ipv6.dst |
    //         tcp.sport | tcp.dport | udp.sport | udp.dport | protocol | info |
    //         tcp.payload | udp.payload | ip.ttl | eth.src |
    //         arp.src.proto_ipv4 | arp.dst.proto_ipv4 | eth.dst
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
            "eth.dst");
    pb.redirectError(ProcessBuilder.Redirect.DISCARD);

    long packetNumber = 0;
    try {
      Process process = pb.start();

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
          String info = (f.length > 11 && !f[11].isEmpty()) ? f[11] : protocol;

          // Extract TTL (field 14) and source MAC (field 15) — best-effort, may be absent
          Integer ttl = null;
          if (f.length > 14 && !f[14].isEmpty()) {
            try {
              ttl = Integer.parseInt(firstValue(f[14]));
            } catch (NumberFormatException ignored) {
            }
          }
          String srcMac =
              (f.length > 15 && !f[15].isEmpty()) ? firstValue(f[15]).toLowerCase() : null;

          // Layer-2 address fallback for non-IP protocols (ARP, STP, LLDP, CDP, etc.).
          // For ARP: use the embedded protocol (IP) addresses from the ARP payload.
          // For other pure L2 frames: use Ethernet MAC addresses as node identifiers.
          String arpSrcIp = (f.length > 16 && !f[16].isEmpty()) ? firstValue(f[16]) : null;
          String arpDstIp = (f.length > 17 && !f[17].isEmpty()) ? firstValue(f[17]) : null;
          String dstMac =
              (f.length > 18 && !f[18].isEmpty()) ? firstValue(f[18]).toLowerCase() : null;
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

            // Extract payload hex from tcp.payload (index 12) or udp.payload (index 13).
            // tshark outputs byte arrays as colon-separated hex pairs (e.g. "48:54:54:50").
            String tsharkPayload = null;
            if (f.length > 12 && !f[12].isEmpty()) {
              tsharkPayload = f[12]; // tcp.payload
            } else if (f.length > 13 && !f[13].isEmpty()) {
              tsharkPayload = f[13]; // udp.payload
            }
            String payloadHex = TsharkHexUtil.toHex(tsharkPayload, PacketEntity.PAYLOAD_BYTE_LIMIT);
            conv.getPackets()
                .add(
                    buildPacketInfo(
                        packetNumber,
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

      int exitCode = process.waitFor();
      if (exitCode != 0 && packetNumber == 0) {
        log.error("tshark exited with code {} and parsed 0 packets", exitCode);
        throw new RuntimeException("tshark failed to parse PCAP file (exit " + exitCode + ")");
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
  }

  @lombok.Data
  public static class ConversationInfo {
    private String srcIp;
    private Integer srcPort;
    private String dstIp;
    private Integer dstPort;
    private String protocol;
    private String appName;
    private String tsharkProtocol;
    private List<String> flowRisks = new ArrayList<>();
    private List<String> customSignatures = new ArrayList<>();
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
