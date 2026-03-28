package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.PacketEntity;
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
import org.pcap4j.packet.namednumber.IpNumber;
import org.springframework.stereotype.Service;

/** Service for parsing PCAP files using Pcap4J with tshark fallback for complex pcapng files */
@Slf4j
@Service
public class PcapParserService {

  private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

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
      int dltValue = handle.getDlt().value();
      // DLT=0  (BSD null/loopback): 4-byte AF header precedes IP.
      // DLT=12 (LINKTYPE_RAW):      no link header — raw IP bytes start at offset 0.
      // DLT=113 (Linux cooked SLL): 16-byte pseudo-header [2 pkt_type][2 hatype][2 halen]
      //                             [8 addr][2 protocol] precedes IP.
      // pcap4j's static factory does not decode these link types, so we handle manually.
      boolean isBsdLoopback = (dltValue == 0);
      boolean isRawIp = (dltValue == 12);
      boolean isLinuxSll = (dltValue == 113);

      try {
        while (true) {
          Packet packet;
          try {
            packet = handle.getNextPacketEx();
          } catch (EOFException e) {
            break; // normal end of capture
          } catch (RuntimeException e) {
            // Pcap4J failed to decode this packet (e.g. malformed/truncated GTPv1 tunnel).
            // Skip it and keep processing the rest of the file.
            log.debug("Skipping malformed packet #{}: {}", packetNumber + 1, e.getMessage());
            packetNumber++;
            continue;
          }
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

          String payloadHex = extractPayloadHex(packet.getRawData());

          IpPacket ipPacket = packet.get(IpPacket.class);
          // 802.1Q / QinQ VLAN frames: pcap4j 1.8.x does not register Dot1qVlanTagPacket
          // in the static EtherType factory, so the VLAN payload is left as UnknownPacket
          // and packet.get(IpPacket.class) returns null.  Unwrap manually via raw bytes.
          if (ipPacket == null) {
            EthernetPacket etherPacket = packet.get(EthernetPacket.class);
            if (etherPacket != null && etherPacket.getPayload() != null) {
              short outerEtherType = etherPacket.getHeader().getType().value();
              byte[] payloadRaw = etherPacket.getPayload().getRawData();
              ipPacket = unwrapVlanToIp(outerEtherType, payloadRaw);
            }
          }
          // BSD null/loopback: raw data is [4-byte AF][IP packet...].
          // Skip the AF header and parse the rest directly as IPv4 or IPv6.
          if (ipPacket == null && isBsdLoopback) {
            byte[] raw = packet.getRawData();
            if (raw != null && raw.length > 4) {
              int version = (raw[4] >> 4) & 0x0F;
              try {
                if (version == 4) {
                  ipPacket = IpV4Packet.newPacket(raw, 4, raw.length - 4);
                } else if (version == 6) {
                  ipPacket = IpV6Packet.newPacket(raw, 4, raw.length - 4);
                }
              } catch (Exception e) {
                log.debug("Failed to parse BSD loopback IP packet", e);
              }
            }
          }
          // DLT=12 (LINKTYPE_RAW): no link-layer header at all — raw IP bytes.
          if (ipPacket == null && isRawIp) {
            byte[] raw = packet.getRawData();
            if (raw != null && raw.length > 0) {
              int version = (raw[0] >> 4) & 0x0F;
              try {
                if (version == 4) ipPacket = IpV4Packet.newPacket(raw, 0, raw.length);
                else if (version == 6) ipPacket = IpV6Packet.newPacket(raw, 0, raw.length);
              } catch (Exception e) {
                log.debug("Failed to parse raw IP packet", e);
              }
            }
          }
          // DLT=113 (Linux cooked / SLL): 16-byte pseudo-header, EtherType at bytes 14-15.
          if (ipPacket == null && isLinuxSll) {
            byte[] raw = packet.getRawData();
            if (raw != null && raw.length > 16) {
              int proto = ((raw[14] & 0xFF) << 8) | (raw[15] & 0xFF);
              int version = (raw[16] >> 4) & 0x0F;
              try {
                if (proto == 0x0800 || version == 4)
                  ipPacket = IpV4Packet.newPacket(raw, 16, raw.length - 16);
                else if (proto == 0x86DD || version == 6)
                  ipPacket = IpV6Packet.newPacket(raw, 16, raw.length - 16);
              } catch (Exception e) {
                log.debug("Failed to parse Linux SLL IP packet", e);
              }
            }
          }
          if (ipPacket != null) {
            processIpPacket(
                ipPacket, packetSize, timestamp, packetNumber, payloadHex, conversationMap, result);
          } else {
            EthernetPacket etherPacket = packet.get(EthernetPacket.class);
            if (etherPacket != null) {
              short outerEtherType = etherPacket.getHeader().getType().value();
              String protoName;
              if ((outerEtherType == (short) 0x8100 || outerEtherType == (short) 0x88A8)
                  && etherPacket.getPayload() != null) {
                protoName =
                    resolveVlanInnerProtocolName(
                        outerEtherType, etherPacket.getPayload().getRawData());
              } else {
                protoName = etherPacket.getHeader().getType().name();
              }
              incrementProtocolCount(result, protoName, packetSize);
            } else {
              incrementProtocolCount(result, "OTHER", packetSize);
            }
          }
        }
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
                        info,
                        null,
                        null)); // payload/app bytes not available via tshark path
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

  /**
   * Peels VLAN layers and returns a human-readable protocol name for the inner EtherType. Used for
   * non-IP VLAN-encapsulated frames (ARP, STP/LLC, LLDP, etc.) so they appear with a meaningful
   * protocol name instead of "IEEE 802.1Q VLAN-tagged frames".
   */
  private String resolveVlanInnerProtocolName(short etherType, byte[] data) {
    int offset = 0;
    while ((etherType == (short) 0x8100 || etherType == (short) 0x88A8)
        && data != null
        && data.length - offset >= 4) {
      etherType = (short) (((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF));
      offset += 4;
    }
    int t = etherType & 0xFFFF;
    if (t <= 1500) return "LLC"; // 802.3 length field → STP/CDP/VTP/etc.
    switch (t) {
      case 0x0800:
        return "IPv4";
      case 0x0806:
        return "ARP";
      case 0x8035:
        return "RARP";
      case 0x86DD:
        return "IPv6";
      case 0x8809:
        return "LACP";
      case 0x8863:
        return "PPPoE-Discovery";
      case 0x8864:
        return "PPPoE";
      case 0x88CC:
        return "LLDP";
      default:
        return String.format("VLAN-0x%04X", t);
    }
  }

  /**
   * Unwraps encapsulation layers from raw Ethernet payload bytes and returns the enclosed IP
   * packet, or {@code null} if the payload does not contain an IP packet.
   *
   * <p>Handled chains (in order):
   *
   * <ol>
   *   <li>802.1Q VLAN (0x8100) / QinQ (0x88A8) — each layer is 4 bytes [TCI][inner EtherType]
   *   <li>PPPoE session (0x8864) — 8-byte header [ver+type][code][session][length][PPP proto] where
   *       PPP proto 0x0021=IPv4, 0x0057=IPv6
   *   <li>Direct IPv4 or IPv6 packet
   * </ol>
   */
  private IpPacket unwrapVlanToIp(short etherType, byte[] data) {
    int offset = 0;
    // Peel 802.1Q (0x8100) and 802.1ad/QinQ (0x88A8) VLAN layers
    while ((etherType == (short) 0x8100 || etherType == (short) 0x88A8)
        && data != null
        && data.length - offset >= 4) {
      etherType = (short) (((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF));
      offset += 4;
    }
    // Peel PPPoE session header (common in DSL/VLAN captures):
    // [1 ver+type=0x11][1 code=0x00][2 session-id][2 payload-len][2 PPP-proto][IP...]
    if (etherType == (short) 0x8864 && data != null && data.length - offset >= 8) {
      int pppProto = ((data[offset + 6] & 0xFF) << 8) | (data[offset + 7] & 0xFF);
      offset += 8;
      if (pppProto != 0x0021 && pppProto != 0x0057) return null; // not IPv4/IPv6
    }
    if (data == null || data.length <= offset) return null;
    int version = (data[offset] >> 4) & 0x0F;
    try {
      if (version == 4) return IpV4Packet.newPacket(data, offset, data.length - offset);
      if (version == 6) return IpV6Packet.newPacket(data, offset, data.length - offset);
    } catch (Exception e) {
      log.debug("Failed to parse VLAN-unwrapped IP packet", e);
    }
    return null;
  }

  private void processIpPacket(
      IpPacket ipPacket,
      int packetSize,
      LocalDateTime timestamp,
      long packetNumber,
      String payloadHex,
      Map<String, ConversationInfo> conversationMap,
      PcapAnalysisResult result) {
    String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
    String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
    String protocol;
    String info;
    Integer srcPort = null;
    Integer dstPort = null;

    byte[] appLayerBytes = null;
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
      if (tcpPacket.getPayload() != null) appLayerBytes = tcpPacket.getPayload().getRawData();
    } else if (ipPacket.get(UdpPacket.class) != null) {
      UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
      protocol = "UDP";
      srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
      dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
      info = srcPort + " \u2192 " + dstPort;
      incrementProtocolCount(result, protocol, packetSize);
      if (udpPacket.getPayload() != null) appLayerBytes = udpPacket.getPayload().getRawData();
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
                info,
                payloadHex,
                appLayerBytes));
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
      String info,
      String payloadHex,
      byte[] appLayerBytes) {

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
    pkt.setDetectedFileType(FileSignatureDetector.detect(appLayerBytes));
    return pkt;
  }

  /**
   * Convert the first {@link PacketEntity#PAYLOAD_BYTE_LIMIT} bytes of raw packet data to a
   * lowercase hex string, or return {@code null} if the input is null or empty.
   */
  private String extractPayloadHex(byte[] raw) {
    if (raw == null || raw.length == 0) return null;
    int limit = Math.min(raw.length, PacketEntity.PAYLOAD_BYTE_LIMIT);
    char[] hexChars = new char[limit * 2];
    for (int i = 0; i < limit; i++) {
      int v = raw[i] & 0xFF;
      hexChars[i * 2] = HEX_ARRAY[v >>> 4];
      hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
    }
    return new String(hexChars);
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

    /** First {@link PacketEntity#PAYLOAD_BYTE_LIMIT} bytes as a lowercase hex string, or null. */
    private String payload;

    /** File type detected from magic bytes, or null if unknown. */
    private String detectedFileType;
  }
}
