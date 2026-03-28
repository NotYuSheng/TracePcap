package com.tracepcap.analysis.service;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.InputStreamReader;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.springframework.stereotype.Service;

/** Service for parsing PCAP files using Pcap4J with tshark fallback for complex pcapng files */
@Slf4j
@Service
public class PcapParserService {

  public PcapAnalysisResult analyzePcapFile(File pcapFile) {
    log.info("Starting PCAP analysis for file: {}", pcapFile.getName());

    // Normalize pcapng snapshot lengths first (fixes libpcap snaplen check)
    File fileToAnalyze = normalizePcapngSnapLen(pcapFile);
    try {
      return analyzePcapFileWithPcap4j(fileToAnalyze);
    } catch (RuntimeException e) {
      // libpcap 1.10.5+ also rejects pcapng with multiple link-layer types;
      // fall back to tshark which handles multi-interface pcapng natively
      if (e.getCause() instanceof PcapNativeException) {
        log.warn("Pcap4J failed ({}), falling back to tshark", e.getCause().getMessage());
        return analyzePcapFileWithTshark(pcapFile);
      }
      throw e;
    } finally {
      if (fileToAnalyze != pcapFile) {
        fileToAnalyze.delete();
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Pcap4J path
  // ---------------------------------------------------------------------------

  private PcapAnalysisResult analyzePcapFileWithPcap4j(File pcapFile) {
    PcapAnalysisResult result = new PcapAnalysisResult();
    result.setProtocolCounts(new HashMap<>());
    result.setProtocolBytes(new HashMap<>());
    result.setConversations(new ArrayList<>());

    Map<String, ConversationInfo> conversationMap = new HashMap<>();

    try (PcapHandle handle = Pcaps.openOffline(pcapFile.getAbsolutePath())) {
      long packetNumber = 0;

      try {
        while (true) {
          Packet packet = handle.getNextPacketEx();
          packetNumber++;

          long timestampSec = handle.getTimestamp().getTime() / 1000;
          LocalDateTime timestamp =
              LocalDateTime.ofInstant(Instant.ofEpochSecond(timestampSec), ZoneId.systemDefault());

          if (result.getStartTime() == null || timestamp.isBefore(result.getStartTime())) {
            result.setStartTime(timestamp);
          }
          if (result.getEndTime() == null || timestamp.isAfter(result.getEndTime())) {
            result.setEndTime(timestamp);
          }

          int packetSize = packet.length();
          result.setTotalBytes(result.getTotalBytes() + packetSize);

          IpPacket ipPacket = packet.get(IpPacket.class);
          if (ipPacket != null) {
            processIpPacket(ipPacket, packetSize, timestamp, packetNumber, conversationMap, result);
          } else {
            EthernetPacket etherPacket = packet.get(EthernetPacket.class);
            if (etherPacket != null) {
              EtherType etherType = etherPacket.getHeader().getType();
              incrementProtocolCount(result, etherType.name(), packetSize);
            } else {
              incrementProtocolCount(result, "OTHER", packetSize);
            }
          }
        }
      } catch (EOFException e) {
        // Normal end of file
      } catch (java.util.concurrent.TimeoutException e) {
        log.warn("Unexpected timeout reading PCAP file after {} packets", result.getPacketCount());
      }

      result.setPacketCount(packetNumber);
      result.setConversations(new ArrayList<>(conversationMap.values()));

      log.info(
          "PCAP analysis completed (Pcap4J): {} packets, {} bytes, {} conversations",
          result.getPacketCount(),
          result.getTotalBytes(),
          result.getConversations().size());

    } catch (PcapNativeException | NotOpenException e) {
      log.error("Pcap4J error: {}", e.getMessage());
      throw new RuntimeException("Failed to analyze PCAP file", e);
    }

    return result;
  }

  // ---------------------------------------------------------------------------
  // tshark fallback path (handles multi-interface / multi-DLT pcapng)
  // ---------------------------------------------------------------------------

  private PcapAnalysisResult analyzePcapFileWithTshark(File pcapFile) {
    log.info("Parsing pcapng with tshark: {}", pcapFile.getName());

    PcapAnalysisResult result = new PcapAnalysisResult();
    result.setProtocolCounts(new HashMap<>());
    result.setProtocolBytes(new HashMap<>());
    result.setConversations(new ArrayList<>());

    Map<String, ConversationInfo> conversationMap = new HashMap<>();

    // Fields: epoch | len | ipv4.src | ipv4.dst | ipv6.src | ipv6.dst |
    //         tcp.sport | tcp.dport | udp.sport | udp.dport | protocol | info
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
            "_ws.col.Info");
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

          // Prefer IPv4, fall back to IPv6
          // tshark may return comma-separated values for tunneled/multi-layer packets — take first
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

          // Track conversations for IP traffic
          if (srcIp != null && dstIp != null) {
            Integer srcPort = null;
            Integer dstPort = null;
            String convProtocol = protocol;

            if (!tcpSport.isEmpty()) {
              srcPort = Integer.parseInt(tcpSport);
              dstPort = Integer.parseInt(tcpDport);
            } else if (!udpSport.isEmpty()) {
              srcPort = Integer.parseInt(udpSport);
              dstPort = Integer.parseInt(udpDport);
            }

            final String fSrcIp = srcIp, fDstIp = dstIp;
            final Integer fSrcPort = srcPort, fDstPort = dstPort;
            final String fProtocol = convProtocol;
            final LocalDateTime fTs = timestamp;

            String convKey = createConversationKey(srcIp, srcPort, dstIp, dstPort, convProtocol);
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
                        info));
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

    log.info(
        "PCAP analysis completed (tshark): {} packets, {} bytes, {} conversations",
        result.getPacketCount(),
        result.getTotalBytes(),
        result.getConversations().size());

    return result;
  }

  // ---------------------------------------------------------------------------
  // pcapng snapshot-length normalizer
  // ---------------------------------------------------------------------------

  /**
   * Patch all IDB SnapLen fields to 65535 so libpcap 1.10.5+ doesn't reject multi-interface pcapng
   * files where interfaces have different snapshot lengths.
   *
   * <p>Uses a stream-copy + memory-mapped in-place patch to avoid loading the entire file into the
   * heap (important for large captures).
   */
  private File normalizePcapngSnapLen(File pcapFile) {
    // Quick pcapng magic check — only read 4 bytes
    try (java.io.FileInputStream fis = new java.io.FileInputStream(pcapFile)) {
      byte[] magic = new byte[4];
      if (fis.read(magic) < 4) return pcapFile;
      boolean isPcapng =
          (magic[0] & 0xFF) == 0x0A
              && (magic[1] & 0xFF) == 0x0D
              && (magic[2] & 0xFF) == 0x0D
              && (magic[3] & 0xFF) == 0x0A;
      if (!isPcapng) return pcapFile;
    } catch (Exception e) {
      return pcapFile;
    }

    try {
      // Stream-copy to temp file so we can patch it without touching the original
      File normalized = File.createTempFile("pcap-normalized-", ".pcapng");
      normalized.deleteOnExit();
      java.nio.file.Files.copy(
          pcapFile.toPath(),
          normalized.toPath(),
          java.nio.file.StandardCopyOption.REPLACE_EXISTING);

      try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(normalized, "rw");
          java.nio.channels.FileChannel ch = raf.getChannel()) {

        if (ch.size() < 12) {
          normalized.delete();
          return pcapFile;
        }

        // Read SHB byte-order magic at offset 8 to determine endianness
        java.nio.ByteBuffer hdr = java.nio.ByteBuffer.allocate(12);
        ch.read(hdr, 0);
        hdr.flip();
        boolean le =
            (hdr.get(8) & 0xFF) == 0x4D
                && (hdr.get(9) & 0xFF) == 0x3C
                && (hdr.get(10) & 0xFF) == 0x2B
                && (hdr.get(11) & 0xFF) == 0x1A;

        // Memory-map the temp file for in-place patching; the OS pages blocks
        // on demand so only accessed regions consume physical RAM
        java.nio.MappedByteBuffer mbb =
            ch.map(java.nio.channels.FileChannel.MapMode.READ_WRITE, 0, ch.size());
        mbb.order(le ? java.nio.ByteOrder.LITTLE_ENDIAN : java.nio.ByteOrder.BIG_ENDIAN);

        boolean patched = false;
        int pos = 0;
        while (pos + 12 <= mbb.limit()) {
          int blockType = mbb.getInt(pos);
          int blockLen = mbb.getInt(pos + 4);
          if (blockLen < 12 || pos + blockLen > mbb.limit()) break;

          // IDB: type(4) + len(4) + link_type(2) + reserved(2) + snap_len(4)
          if (blockType == 1 && pos + 16 <= mbb.limit()) {
            mbb.putInt(pos + 12, 65535);
            patched = true;
          }
          pos += blockLen;
        }

        mbb.force();

        if (!patched) {
          normalized.delete();
          return pcapFile;
        }
      }

      return normalized;
    } catch (Exception e) {
      log.warn("Failed to normalize pcapng snaplen: {}", e.getMessage());
      return pcapFile;
    }
  }

  // ---------------------------------------------------------------------------
  // Shared helpers
  // ---------------------------------------------------------------------------

  private void processIpPacket(
      IpPacket ipPacket,
      int packetSize,
      LocalDateTime timestamp,
      long packetNumber,
      Map<String, ConversationInfo> conversationMap,
      PcapAnalysisResult result) {
    String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
    String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
    String protocol;
    String info;
    Integer srcPort = null;
    Integer dstPort = null;

    TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
    if (tcpPacket != null) {
      protocol = "TCP";
      srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
      dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
      TcpPacket.TcpHeader h = tcpPacket.getHeader();
      List<String> flags = new ArrayList<>();
      if (h.getSyn()) flags.add("SYN");
      if (h.getAck()) flags.add("ACK");
      if (h.getFin()) flags.add("FIN");
      if (h.getRst()) flags.add("RST");
      if (h.getPsh()) flags.add("PSH");
      if (h.getUrg()) flags.add("URG");
      String flagStr = flags.isEmpty() ? "" : " [" + String.join(", ", flags) + "]";
      info = srcPort + " \u2192 " + dstPort + flagStr;
      incrementProtocolCount(result, protocol, packetSize);
    } else if (ipPacket.get(UdpPacket.class) != null) {
      UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
      protocol = "UDP";
      srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
      dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
      info = srcPort + " \u2192 " + dstPort;
      incrementProtocolCount(result, protocol, packetSize);
    } else if (ipPacket.get(IcmpV4CommonPacket.class) != null) {
      protocol = "ICMP";
      info = "ICMP";
      incrementProtocolCount(result, protocol, packetSize);
    } else {
      IpNumber ipNumber = ipPacket.getHeader().getProtocol();
      protocol = ipNumber.name();
      info = protocol;
      incrementProtocolCount(result, protocol, packetSize);
    }

    String convKey = createConversationKey(srcIp, srcPort, dstIp, dstPort, protocol);
    final String fSrcIp = srcIp, fDstIp = dstIp;
    final Integer fSrcPort = srcPort, fDstPort = dstPort;
    final String fProtocol = protocol;
    final LocalDateTime fTs = timestamp;

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
                info));
  }

  private PacketInfo buildPacketInfo(
      long packetNumber,
      LocalDateTime timestamp,
      String srcIp,
      Integer srcPort,
      String dstIp,
      Integer dstPort,
      String protocol,
      int packetSize,
      String info) {
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
  }

  @lombok.Data
  public static class ConversationInfo {
    private String srcIp;
    private Integer srcPort;
    private String dstIp;
    private Integer dstPort;
    private String protocol;
    private String appName;
    private List<String> flowRisks = new ArrayList<>();
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
  }
}
