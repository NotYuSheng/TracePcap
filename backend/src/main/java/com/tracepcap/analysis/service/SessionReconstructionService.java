package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.SessionResponse;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.service.StorageService;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reconstructs the full TCP/UDP byte stream for a conversation using {@code tshark -z follow} and
 * decodes the application-layer payload.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SessionReconstructionService {

  /** Maximum bytes to reconstruct before truncating. */
  private static final long MAX_SESSION_BYTES = 1_048_576; // 1 MB

  /** Maximum body bytes to include in an HTTP message. */
  private static final int MAX_BODY_DISPLAY_BYTES = 65_536; // 64 KB

  /** Refuse reconstruction for PCAP files larger than this to protect disk/I/O. */
  private static final long MAX_PCAP_FILE_BYTES = 500L * 1024 * 1024; // 500 MB

  private final ConversationRepository conversationRepository;
  private final StorageService storageService;

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  @Transactional(readOnly = true)
  public SessionResponse reconstruct(UUID conversationId) {
    ConversationEntity conv =
        conversationRepository
            .findById(conversationId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Conversation not found: " + conversationId));

    // Refuse to download files that would be excessively large
    Long pcapSize = conv.getFile().getFileSize();
    if (pcapSize != null && pcapSize > MAX_PCAP_FILE_BYTES) {
      return error(
          String.format(
              "Capture file is too large for session reconstruction (%.0f MB). "
                  + "The limit is %d MB.",
              pcapSize / 1_048_576.0, MAX_PCAP_FILE_BYTES / 1_048_576));
    }

    File tempFile = null;
    try {
      tempFile = File.createTempFile("session-", ".pcap");
      log.debug(
          "Downloading {} bytes from {} for session reconstruction",
          pcapSize,
          conv.getFile().getMinioPath());
      storageService.downloadFileToLocal(conv.getFile().getMinioPath(), tempFile);
      return doReconstruct(conv, tempFile);
    } catch (ResourceNotFoundException e) {
      throw e;
    } catch (Exception e) {
      log.error("Session reconstruction failed for {}: {}", conversationId, e.getMessage(), e);
      return error("Reconstruction failed: " + e.getMessage());
    } finally {
      if (tempFile != null && !tempFile.delete()) {
        tempFile.deleteOnExit();
      }
    }
  }

  // -------------------------------------------------------------------------
  // Core reconstruction
  // -------------------------------------------------------------------------

  private SessionResponse doReconstruct(ConversationEntity conv, File pcapFile) throws Exception {

    // The stored protocol is the highest-level protocol tshark saw (HTTP, TLS, DNS, etc.).
    // We need the transport layer, so try tcp then udp regardless of what is stored.
    StreamLocation loc = findStreamIndex(pcapFile, conv);
    if (loc == null) {
      return error(
          "Could not locate this conversation's stream in the capture file. "
              + "The conversation may not contain payload data.");
    }
    String followProto = loc.proto;

    List<RawChunk> rawChunks = runFollowCommand(pcapFile, followProto, loc.streamIndex, conv);

    long clientBytes =
        rawChunks.stream()
            .filter(c -> "CLIENT".equals(c.direction))
            .mapToLong(c -> c.data.length)
            .sum();
    long serverBytes =
        rawChunks.stream()
            .filter(c -> "SERVER".equals(c.direction))
            .mapToLong(c -> c.data.length)
            .sum();
    boolean truncated = (clientBytes + serverBytes) >= MAX_SESSION_BYTES;

    String detectedProtocol = detectProtocol(conv, rawChunks);

    List<SessionResponse.Chunk> chunks = buildChunks(rawChunks);

    List<SessionResponse.HttpExchange> httpExchanges = null;
    if ("HTTP".equals(detectedProtocol)) {
      httpExchanges = parseHttpExchanges(rawChunks);
    }

    List<SessionResponse.StunMessage> stunMessages = null;
    if ("STUN".equals(detectedProtocol)) {
      stunMessages = parseStunMessages(rawChunks);
    }

    return SessionResponse.builder()
        .detectedProtocol(detectedProtocol)
        .chunks(chunks)
        .httpExchanges(httpExchanges)
        .stunMessages(stunMessages)
        .truncated(truncated)
        .totalClientBytes(clientBytes)
        .totalServerBytes(serverBytes)
        .build();
  }

  // -------------------------------------------------------------------------
  // Stream index lookup
  // -------------------------------------------------------------------------

  /**
   * Finds the tshark stream index for the conversation by trying both TCP and UDP, and both
   * endpoint directions. Returns a {@link StreamLocation} with the transport protocol and index, or
   * {@code null} if the stream cannot be found.
   *
   * <p>The protocol stored on the conversation entity is the application-layer protocol (HTTP, TLS,
   * DNS, …) not the transport, so we probe both transports unconditionally.
   */
  private StreamLocation findStreamIndex(File pcapFile, ConversationEntity conv) throws Exception {
    for (String transport : new String[] {"tcp", "udp"}) {
      // Try both endpoint directions — the entity's srcIp may or may not be the packet source
      for (int flip = 0; flip < 2; flip++) {
        String srcIp = flip == 0 ? conv.getSrcIp() : conv.getDstIp();
        String dstIp = flip == 0 ? conv.getDstIp() : conv.getSrcIp();
        Integer srcPort = flip == 0 ? conv.getSrcPort() : conv.getDstPort();
        Integer dstPort = flip == 0 ? conv.getDstPort() : conv.getSrcPort();

        Integer idx = queryStreamIndex(pcapFile, transport, srcIp, srcPort, dstIp, dstPort);
        if (idx != null) {
          log.debug("Found {}.stream={} for conversation {}", transport, idx, conv.getId());
          return new StreamLocation(transport, idx);
        }
      }
    }
    return null;
  }

  private Integer queryStreamIndex(
      File pcapFile, String transport, String srcIp, Integer srcPort, String dstIp, Integer dstPort)
      throws Exception {

    String streamField = transport + ".stream";
    String filter = buildFilter(transport, srcIp, srcPort, dstIp, dstPort);

    ProcessBuilder pb =
        new ProcessBuilder(
            "tshark",
            "-r",
            pcapFile.getAbsolutePath(),
            "-Y",
            filter,
            "-e",
            streamField,
            "-T",
            "fields");
    pb.redirectError(ProcessBuilder.Redirect.DISCARD);
    Process process = pb.start();

    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(process.getInputStream()))) {
      String line;
      while ((line = reader.readLine()) != null) {
        line = line.trim();
        if (!line.isEmpty()) {
          try {
            int idx = Integer.parseInt(line);
            process.destroy(); // no need to read the rest of the pcap
            return idx;
          } catch (NumberFormatException ignored) {
          }
        }
      }
    }
    process.waitFor();
    return null;
  }

  private String buildFilter(
      String transport, String srcIp, Integer srcPort, String dstIp, Integer dstPort) {

    String ipProto = (srcIp != null && srcIp.contains(":")) ? "ipv6" : "ip";
    StringBuilder sb = new StringBuilder();
    sb.append(ipProto).append(".src==").append(srcIp);
    if (srcPort != null) sb.append(" && ").append(transport).append(".srcport==").append(srcPort);
    sb.append(" && ").append(ipProto).append(".dst==").append(dstIp);
    if (dstPort != null) sb.append(" && ").append(transport).append(".dstport==").append(dstPort);
    return sb.toString();
  }

  // -------------------------------------------------------------------------
  // tshark follow command
  // -------------------------------------------------------------------------

  /**
   * Runs {@code tshark -q -z follow,<proto>,raw,<N>} and returns the ordered raw byte chunks. Each
   * chunk is tagged CLIENT (Node0) or SERVER (Node1) based on the follow header.
   */
  private List<RawChunk> runFollowCommand(
      File pcapFile, String proto, int streamIndex, ConversationEntity conv) throws Exception {

    List<String> cmd =
        List.of(
            "tshark",
            "-r",
            pcapFile.getAbsolutePath(),
            "-q",
            "-z",
            "follow," + proto + ",raw," + streamIndex);

    ProcessBuilder pb = new ProcessBuilder(cmd);
    pb.redirectError(ProcessBuilder.Redirect.DISCARD);
    Process process = pb.start();

    List<RawChunk> chunks = new ArrayList<>();
    String node0Direction = null; // "CLIENT" or "SERVER"

    // Accumulate consecutive same-direction bytes in a stream to avoid O(N²) array copies
    ByteArrayOutputStream accumulator = new ByteArrayOutputStream();
    String currentDirection = null;

    long totalBytes = 0;
    boolean truncated = false;

    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(process.getInputStream()))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("===")) continue;
        if (line.startsWith("Filter:")) continue;
        if (line.startsWith("Node0:")) {
          String node0Ip = extractIp(line.substring("Node0:".length()));
          node0Direction = node0Ip.equals(conv.getSrcIp()) ? "CLIENT" : "SERVER";
          continue;
        }
        if (line.startsWith("Node1:")) continue;
        if (line.isBlank()) continue;

        if (truncated) continue; // drain stdout without processing

        boolean isNode1 = line.startsWith("\t");
        String hexLine = isNode1 ? line.stripLeading() : line;
        if (hexLine.isBlank()) continue;

        String direction =
            (node0Direction == null)
                ? (isNode1 ? "SERVER" : "CLIENT")
                : (isNode1 ? opposite(node0Direction) : node0Direction);

        byte[] data = hexToBytes(hexLine);
        if (data == null || data.length == 0) continue;

        // Handle truncation: include bytes up to the limit then stop accumulating
        if (totalBytes + data.length > MAX_SESSION_BYTES) {
          truncated = true;
          int remaining = (int) (MAX_SESSION_BYTES - totalBytes);
          if (remaining > 0) {
            if (!direction.equals(currentDirection)) {
              flushAccumulator(chunks, accumulator, currentDirection);
              currentDirection = direction;
            }
            accumulator.write(data, 0, remaining);
            totalBytes += remaining;
          }
          continue;
        }

        totalBytes += data.length;

        if (!direction.equals(currentDirection)) {
          flushAccumulator(chunks, accumulator, currentDirection);
          currentDirection = direction;
        }
        accumulator.write(data);
      }
    }
    // Flush any remaining accumulated bytes
    flushAccumulator(chunks, accumulator, currentDirection);

    process.waitFor();
    return chunks;
  }

  private void flushAccumulator(
      List<RawChunk> chunks, ByteArrayOutputStream accumulator, String direction) {
    if (direction != null && accumulator.size() > 0) {
      chunks.add(new RawChunk(direction, accumulator.toByteArray()));
      accumulator.reset();
    }
  }

  private String extractIp(String nodeStr) {
    // Format: <ip>:<port>  — handle IPv6 like "[::1]:80"
    int lastColon = nodeStr.lastIndexOf(':');
    if (lastColon < 0) return nodeStr;
    return nodeStr.substring(0, lastColon);
  }

  private String opposite(String direction) {
    return "CLIENT".equals(direction) ? "SERVER" : "CLIENT";
  }

  // -------------------------------------------------------------------------
  // Protocol detection
  // -------------------------------------------------------------------------

  private String detectProtocol(ConversationEntity conv, List<RawChunk> chunks) {
    // Prefer tshark/nDPI metadata first
    String tshark = conv.getTsharkProtocol();
    if (tshark != null) {
      String upper = tshark.toUpperCase();
      if (upper.contains("HTTP")) return "HTTP";
      if (upper.contains("TLS") || upper.contains("SSL")) return "TLS";
      if (upper.contains("FTP")) return "FTP";
      if (upper.contains("SMTP")) return "SMTP";
      if (upper.contains("IMAP")) return "IMAP";
      if (upper.contains("POP")) return "POP3";
      if (upper.contains("DNS")) return "DNS";
      if (upper.contains("STUN")) return "STUN";
    }
    String app = conv.getAppName();
    if (app != null) {
      String upper = app.toUpperCase();
      if (upper.contains("HTTP")) return "HTTP";
      if (upper.contains("TLS") || upper.contains("SSL")) return "TLS";
      if (upper.contains("STUN")) return "STUN";
    }

    // Sniff first client bytes
    for (RawChunk chunk : chunks) {
      if ("CLIENT".equals(chunk.direction) && chunk.data.length >= 4) {
        String prefix =
            new String(
                Arrays.copyOf(chunk.data, Math.min(8, chunk.data.length)),
                StandardCharsets.US_ASCII);
        if (prefix.startsWith("GET ")
            || prefix.startsWith("POST")
            || prefix.startsWith("HEAD")
            || prefix.startsWith("PUT ")
            || prefix.startsWith("DELE")
            || prefix.startsWith("OPTI")
            || prefix.startsWith("PATC")
            || prefix.startsWith("HTTP")) {
          return "HTTP";
        }
        if (prefix.startsWith("EHLO") || prefix.startsWith("HELO") || prefix.startsWith("MAIL")) {
          return "SMTP";
        }
        if (prefix.startsWith("USER") || prefix.startsWith("PASS") || prefix.startsWith("RETR")) {
          return "FTP";
        }
        // TLS ClientHello starts with 0x16 0x03
        if (chunk.data[0] == 0x16 && chunk.data[1] == 0x03) return "TLS";
        // STUN magic cookie 0x2112A442 at bytes 4-7
        if (chunk.data.length >= 20 && isStunPacket(chunk.data, 0)) return "STUN";
        break;
      }
    }

    // Port-based heuristic
    Integer port = conv.getDstPort() != null ? conv.getDstPort() : conv.getSrcPort();
    if (port != null) {
      return switch (port) {
        case 80, 8080, 8000, 8888 -> "HTTP";
        case 443, 8443 -> "TLS";
        case 25, 465, 587 -> "SMTP";
        case 110, 995 -> "POP3";
        case 143, 993 -> "IMAP";
        case 21 -> "FTP";
        case 53 -> "DNS";
        case 3478, 5349 -> "STUN";
        default -> "RAW";
      };
    }
    return "RAW";
  }

  // -------------------------------------------------------------------------
  // Chunk display formatting
  // -------------------------------------------------------------------------

  private List<SessionResponse.Chunk> buildChunks(List<RawChunk> rawChunks) {
    List<SessionResponse.Chunk> result = new ArrayList<>();
    for (RawChunk rc : rawChunks) {
      boolean binary = !isPrintableAscii(rc.data);
      String text = binary ? formatHexDump(rc.data) : new String(rc.data, StandardCharsets.UTF_8);
      result.add(
          SessionResponse.Chunk.builder()
              .direction(rc.direction)
              .text(text)
              .binary(binary)
              .byteLength(rc.data.length)
              .build());
    }
    return result;
  }

  // -------------------------------------------------------------------------
  // STUN parsing (RFC 5389 / 8489)
  // -------------------------------------------------------------------------

  private static final int STUN_MAGIC_COOKIE = 0x2112A442;

  /**
   * Returns true if the bytes at {@code offset} look like the start of a STUN message: the STUN
   * magic cookie must appear at bytes 4–7.
   */
  private boolean isStunPacket(byte[] data, int offset) {
    if (offset + 20 > data.length) return false;
    int cookie =
        ((data[offset + 4] & 0xFF) << 24)
            | ((data[offset + 5] & 0xFF) << 16)
            | ((data[offset + 6] & 0xFF) << 8)
            | (data[offset + 7] & 0xFF);
    return cookie == STUN_MAGIC_COOKIE;
  }

  private List<SessionResponse.StunMessage> parseStunMessages(List<RawChunk> rawChunks) {
    List<SessionResponse.StunMessage> result = new ArrayList<>();
    for (RawChunk chunk : rawChunks) {
      // For UDP each chunk is typically one STUN datagram; for TCP there is a 4-byte framing
      // header per RFC 4571 (2-byte length + the message). We attempt both.
      parseStunFromBytes(chunk.data, chunk.direction, result);
    }
    return result;
  }

  private void parseStunFromBytes(byte[] data, String direction, List<SessionResponse.StunMessage> out) {
    int pos = 0;
    while (pos + 20 <= data.length) {
      // Try with TCP framing (2-byte big-endian length prefix)
      int tcpFrameLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
      if (pos + 2 + tcpFrameLen <= data.length && isStunPacket(data, pos + 2)) {
        SessionResponse.StunMessage msg = decodeStunMessage(data, pos + 2, direction);
        if (msg != null) {
          out.add(msg);
          pos += 2 + tcpFrameLen;
          continue;
        }
      }
      // Try without framing (bare UDP datagram)
      if (isStunPacket(data, pos)) {
        int msgLen = ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
        SessionResponse.StunMessage msg = decodeStunMessage(data, pos, direction);
        if (msg != null) {
          out.add(msg);
          pos += 20 + msgLen;
          continue;
        }
      }
      break; // not a recognisable STUN message — stop scanning this chunk
    }
  }

  private SessionResponse.StunMessage decodeStunMessage(byte[] data, int offset, String direction) {
    if (offset + 20 > data.length) return null;

    int typeField = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    int msgLen = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);

    // Transaction ID: bytes 8–19
    StringBuilder txId = new StringBuilder();
    for (int i = 8; i < 20; i++) {
      txId.append(String.format("%02x", data[offset + i] & 0xFF));
    }

    String messageClass = decodeStunClass(typeField);
    String messageType = decodeStunMethod(typeField, messageClass);

    // Transaction ID as raw bytes (bytes 8–19) — needed for IPv6 XOR-MAPPED-ADDRESS decoding
    byte[] txIdBytes = Arrays.copyOfRange(data, offset + 8, offset + 20);

    Map<String, String> attributes = new LinkedHashMap<>();

    // Decode attributes
    int attrOffset = offset + 20;
    int attrEnd = Math.min(attrOffset + msgLen, data.length);
    while (attrOffset + 4 <= attrEnd) {
      int attrType = ((data[attrOffset] & 0xFF) << 8) | (data[attrOffset + 1] & 0xFF);
      int attrLen = ((data[attrOffset + 2] & 0xFF) << 8) | (data[attrOffset + 3] & 0xFF);
      int valueOffset = attrOffset + 4;
      int valueEnd = Math.min(valueOffset + attrLen, attrEnd);

      String attrName = stunAttributeName(attrType);
      String attrValue = decodeStunAttribute(attrType, data, valueOffset, valueEnd - valueOffset, txIdBytes);
      attributes.put(attrName, attrValue);

      // Attributes are padded to 4-byte boundaries
      attrOffset += 4 + ((attrLen + 3) & ~3);
    }

    return SessionResponse.StunMessage.builder()
        .direction(direction)
        .messageType(messageType)
        .messageClass(messageClass)
        .transactionId(txId.toString())
        .attributes(attributes)
        .build();
  }

  /** Decodes the 2-bit STUN message class from the 14-bit type field. */
  private String decodeStunClass(int typeField) {
    // Bits C1 and C0 are at positions 8 and 4 of the 14-bit field (RFC 5389 §6)
    int c1 = (typeField >> 8) & 0x01;
    int c0 = (typeField >> 4) & 0x01;
    int cls = (c1 << 1) | c0;
    return switch (cls) {
      case 0b00 -> "Request";
      case 0b01 -> "Indication";
      case 0b10 -> "Success Response";
      case 0b11 -> "Error Response";
      default -> "Unknown";
    };
  }

  /** Decodes the STUN method from the type field and returns a human-readable message type. */
  private String decodeStunMethod(int typeField, String messageClass) {
    // Extract method bits: bits 13-10, 8-5, 3-0 (masking out the class bits)
    int method = (typeField & 0x3E00) >> 2 | (typeField & 0x00E0) >> 1 | (typeField & 0x000F);
    String methodName =
        switch (method) {
          case 0x001 -> "Binding";
          case 0x003 -> "Allocate";
          case 0x004 -> "Refresh";
          case 0x006 -> "Send";
          case 0x007 -> "Data";
          case 0x008 -> "CreatePermission";
          case 0x009 -> "ChannelBind";
          default -> String.format("Unknown(0x%03x)", method);
        };
    return methodName + " " + messageClass;
  }

  private String stunAttributeName(int attrType) {
    return switch (attrType) {
      case 0x0001 -> "MAPPED-ADDRESS";
      case 0x0006 -> "USERNAME";
      case 0x0008 -> "MESSAGE-INTEGRITY";
      case 0x0009 -> "ERROR-CODE";
      case 0x000A -> "UNKNOWN-ATTRIBUTES";
      case 0x0014 -> "REALM";
      case 0x0015 -> "NONCE";
      case 0x0020 -> "XOR-MAPPED-ADDRESS";
      case 0x0024 -> "PRIORITY";
      case 0x0025 -> "USE-CANDIDATE";
      case 0x0026 -> "ICE-CONTROLLED";  // or ICE-CONTROLLING depending on value
      case 0x0027 -> "ICE-CONTROLLING";
      case 0x002B -> "RESPONSE-ORIGIN";
      case 0x002C -> "OTHER-ADDRESS";
      case 0x8022 -> "SOFTWARE";
      case 0x8023 -> "ALTERNATE-SERVER";
      case 0x8025 -> "TRANSACTION-TRANSMIT-COUNTER";
      case 0x8028 -> "FINGERPRINT";
      case 0x8029 -> "ICE-CONTROLLED";
      case 0x802A -> "ICE-CONTROLLING";
      case 0xC057 -> "NETWORK-COST";
      default -> String.format("0x%04X", attrType);
    };
  }

  private String decodeStunAttribute(int attrType, byte[] data, int offset, int length, byte[] txId) {
    if (length <= 0 || offset + length > data.length) return "(empty)";
    try {
      return switch (attrType) {
        case 0x0001 -> decodeMappedAddress(data, offset, false, null);
        case 0x0020 -> decodeMappedAddress(data, offset, true, txId);
        case 0x0006, 0x0014, 0x0015, 0x8022 ->
            new String(data, offset, length, StandardCharsets.UTF_8);
        case 0x0009 -> decodeErrorCode(data, offset, length);
        case 0x0008, 0x8028 -> bytesToHex(data, offset, Math.min(length, 20));
        case 0x0024 -> {
          if (length >= 4) {
            long priority =
                ((data[offset] & 0xFFL) << 24)
                    | ((data[offset + 1] & 0xFFL) << 16)
                    | ((data[offset + 2] & 0xFFL) << 8)
                    | (data[offset + 3] & 0xFFL);
            yield String.valueOf(priority);
          }
          yield bytesToHex(data, offset, length);
        }
        default -> bytesToHex(data, offset, Math.min(length, 16));
      };
    } catch (Exception e) {
      return "(parse error)";
    }
  }

  /** Decodes MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute (IPv4 and IPv6). */
  private String decodeMappedAddress(byte[] data, int offset, boolean xor, byte[] txId) {
    if (offset + 4 > data.length) return "(truncated)";
    int family = data[offset + 1] & 0xFF;
    int port = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
    if (xor) {
      port ^= (STUN_MAGIC_COOKIE >> 16) & 0xFFFF;
    }
    if (family == 0x01) {
      // IPv4
      if (offset + 8 > data.length) return "(truncated)";
      byte[] ipBytes = Arrays.copyOfRange(data, offset + 4, offset + 8);
      if (xor) {
        int ipInt = java.nio.ByteBuffer.wrap(ipBytes).getInt() ^ STUN_MAGIC_COOKIE;
        java.nio.ByteBuffer.wrap(ipBytes).putInt(ipInt);
      }
      try {
        return java.net.InetAddress.getByAddress(ipBytes).getHostAddress() + ":" + port;
      } catch (java.net.UnknownHostException e) {
        return "(invalid IPv4):" + port;
      }
    } else if (family == 0x02) {
      // IPv6 — XOR key is magic cookie (4 bytes) + transaction ID (12 bytes)
      if (offset + 20 > data.length) return "(truncated)";
      byte[] ipBytes = Arrays.copyOfRange(data, offset + 4, offset + 20);
      if (xor && txId != null && txId.length == 12) {
        byte[] xorKey = new byte[16];
        java.nio.ByteBuffer.wrap(xorKey).putInt(STUN_MAGIC_COOKIE).put(txId);
        for (int i = 0; i < 16; i++) ipBytes[i] ^= xorKey[i];
      }
      try {
        return "[" + java.net.InetAddress.getByAddress(ipBytes).getHostAddress() + "]:" + port;
      } catch (java.net.UnknownHostException e) {
        return "(invalid IPv6):" + port;
      }
    }
    return "(unknown family)";
  }

  private String decodeErrorCode(byte[] data, int offset, int length) {
    if (length < 4) return "(truncated)";
    int cls = (data[offset + 2] & 0x07);
    int num = data[offset + 3] & 0xFF;
    int code = cls * 100 + num;
    String reason =
        length > 4
            ? new String(data, offset + 4, length - 4, StandardCharsets.UTF_8).trim()
            : "";
    return reason.isEmpty() ? String.valueOf(code) : code + " " + reason;
  }

  private String bytesToHex(byte[] data, int offset, int length) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < length && offset + i < data.length; i++) {
      if (i > 0) sb.append(':');
      sb.append(String.format("%02x", data[offset + i] & 0xFF));
    }
    return sb.toString();
  }

  // -------------------------------------------------------------------------
  // HTTP parsing
  // -------------------------------------------------------------------------

  private List<SessionResponse.HttpExchange> parseHttpExchanges(List<RawChunk> rawChunks) {
    byte[] clientStream = mergeStream(rawChunks, "CLIENT");
    byte[] serverStream = mergeStream(rawChunks, "SERVER");

    List<byte[]> requests = splitHttpMessages(clientStream, true);
    List<byte[]> responses = splitHttpMessages(serverStream, false);

    List<SessionResponse.HttpExchange> exchanges = new ArrayList<>();
    int count = Math.max(requests.size(), responses.size());
    for (int i = 0; i < count; i++) {
      SessionResponse.HttpMessage req =
          i < requests.size() ? parseHttpMessage(requests.get(i)) : null;
      SessionResponse.HttpMessage resp =
          i < responses.size() ? parseHttpMessage(responses.get(i)) : null;
      if (req != null || resp != null) {
        exchanges.add(SessionResponse.HttpExchange.builder().request(req).response(resp).build());
      }
    }
    return exchanges;
  }

  private byte[] mergeStream(List<RawChunk> chunks, String direction) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (RawChunk c : chunks) {
      if (direction.equals(c.direction)) {
        out.write(c.data, 0, c.data.length);
      }
    }
    return out.toByteArray();
  }

  /**
   * Splits a raw HTTP byte stream into individual messages by parsing sequentially.
   *
   * <p>Rather than scanning the whole buffer for start-line patterns (which causes false positives
   * when those strings appear inside a message body), this method:
   *
   * <ol>
   *   <li>Anchors to the first message at position 0 (or skips leading garbage).
   *   <li>Parses headers to determine body length via {@code Content-Length} or chunked encoding.
   *   <li>Jumps to the exact byte after the body end to find the next message.
   * </ol>
   */
  private List<byte[]> splitHttpMessages(byte[] stream, boolean isRequest) {
    List<byte[]> messages = new ArrayList<>();
    if (stream.length == 0) return messages;

    String[] patternStrings =
        isRequest
            ? new String[] {
              "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "
            }
            : new String[] {"HTTP/1.0 ", "HTTP/1.1 ", "HTTP/2 "};

    int pos = 0;
    while (pos < stream.length) {
      // Find the next message start at or after pos
      int msgStart = -1;
      for (String pat : patternStrings) {
        byte[] pb = pat.getBytes(StandardCharsets.US_ASCII);
        // Only check at the current position to avoid scanning into bodies
        if (matchesAt(stream, pos, pb)) {
          msgStart = pos;
          break;
        }
      }

      if (msgStart < 0) {
        // Current position doesn't look like a message start.
        // Scan forward one line at a time (handles leading junk or pipelining gaps).
        int nl = indexOf(stream, pos, new byte[] {'\n'});
        if (nl < 0) break;
        pos = nl + 1;
        continue;
      }

      // Find end of headers (\r\n\r\n or \n\n)
      byte[] crlfcrlf = "\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
      byte[] lflf = "\n\n".getBytes(StandardCharsets.US_ASCII);
      int headerEnd = indexOf(stream, msgStart, crlfcrlf);
      int bodyStart;
      if (headerEnd >= 0) {
        bodyStart = headerEnd + 4;
      } else {
        headerEnd = indexOf(stream, msgStart, lflf);
        bodyStart = (headerEnd >= 0) ? headerEnd + 2 : stream.length;
      }

      if (headerEnd < 0) {
        // Incomplete headers — grab the rest and stop
        messages.add(Arrays.copyOfRange(stream, msgStart, stream.length));
        break;
      }

      // Parse headers for body length
      String headerSection =
          new String(Arrays.copyOfRange(stream, msgStart, headerEnd), StandardCharsets.ISO_8859_1);
      String[] lines = headerSection.split("\r?\n", -1);

      int contentLength = -1;
      boolean chunked = false;
      for (int i = 1; i < lines.length; i++) {
        String lower = lines[i].toLowerCase(java.util.Locale.ROOT);
        if (lower.startsWith("content-length:")) {
          try {
            contentLength = Integer.parseInt(lines[i].substring(lines[i].indexOf(':') + 1).trim());
          } catch (NumberFormatException ignored) {
          }
        } else if (lower.startsWith("transfer-encoding:") && lower.contains("chunked")) {
          chunked = true;
        }
      }

      int msgEnd;
      if (contentLength >= 0) {
        msgEnd = Math.min(bodyStart + contentLength, stream.length);
      } else if (chunked) {
        msgEnd = findChunkedBodyEnd(stream, bodyStart);
      } else {
        // No body length — assume this message runs to the end of the stream
        msgEnd = stream.length;
      }

      messages.add(Arrays.copyOfRange(stream, msgStart, msgEnd));
      pos = msgEnd;
    }

    if (messages.isEmpty() && stream.length > 0) {
      messages.add(stream);
    }
    return messages;
  }

  /** Returns true when {@code stream[at..at+pattern.length]} equals {@code pattern}. */
  private boolean matchesAt(byte[] stream, int at, byte[] pattern) {
    if (at + pattern.length > stream.length) return false;
    for (int i = 0; i < pattern.length; i++) {
      if (stream[at + i] != pattern[i]) return false;
    }
    return true;
  }

  /** Returns the byte position immediately after the terminal zero-chunk of a chunked body. */
  private int findChunkedBodyEnd(byte[] stream, int start) {
    int pos = start;
    byte[] crlf = "\r\n".getBytes(StandardCharsets.US_ASCII);
    while (pos < stream.length) {
      int lineEnd = indexOf(stream, pos, crlf);
      if (lineEnd < 0) return stream.length;
      String sizeLine =
          new String(Arrays.copyOfRange(stream, pos, lineEnd), StandardCharsets.US_ASCII).trim();
      int semi = sizeLine.indexOf(';');
      if (semi >= 0) sizeLine = sizeLine.substring(0, semi).trim();
      try {
        int chunkSize = Integer.parseInt(sizeLine, 16);
        pos = lineEnd + 2 + chunkSize + 2; // chunk-size CRLF data CRLF
        if (chunkSize == 0) return Math.min(pos, stream.length);
      } catch (NumberFormatException e) {
        return stream.length;
      }
    }
    return stream.length;
  }

  private SessionResponse.HttpMessage parseHttpMessage(byte[] raw) {
    if (raw == null || raw.length == 0) return null;

    // Split headers from body at \r\n\r\n (or \n\n)
    int headerEnd = indexOf(raw, "\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
    int bodyStart;
    if (headerEnd >= 0) {
      bodyStart = headerEnd + 4;
    } else {
      headerEnd = indexOf(raw, "\n\n".getBytes(StandardCharsets.US_ASCII));
      bodyStart = headerEnd >= 0 ? headerEnd + 2 : raw.length;
    }

    String headerSection =
        new String(
            Arrays.copyOf(raw, headerEnd >= 0 ? headerEnd : raw.length),
            StandardCharsets.ISO_8859_1);

    String[] headerLines = headerSection.split("\r?\n", -1);
    String firstLine = headerLines.length > 0 ? headerLines[0] : "";

    Map<String, String> headers = new LinkedHashMap<>();
    for (int i = 1; i < headerLines.length; i++) {
      int colon = headerLines[i].indexOf(':');
      if (colon > 0) {
        String name = headerLines[i].substring(0, colon).trim().toLowerCase();
        String value = headerLines[i].substring(colon + 1).trim();
        headers.merge(name, value, (a, b) -> a + ", " + b);
      }
    }

    // Extract body
    byte[] bodyBytes =
        bodyStart < raw.length ? Arrays.copyOfRange(raw, bodyStart, raw.length) : new byte[0];

    // Handle chunked transfer encoding — decode chunks
    String transferEncoding = headers.getOrDefault("transfer-encoding", "");
    if (transferEncoding.toLowerCase().contains("chunked")) {
      bodyBytes = decodeChunked(bodyBytes);
    } else {
      // Respect Content-Length if present
      String contentLength = headers.get("content-length");
      if (contentLength != null) {
        try {
          int len = Integer.parseInt(contentLength.trim());
          if (len < bodyBytes.length) bodyBytes = Arrays.copyOf(bodyBytes, len);
        } catch (NumberFormatException ignored) {
        }
      }
    }

    long actualBodyLength = bodyBytes.length;

    // Handle content-encoding (gzip / deflate)
    boolean decompressed = false;
    String bodyEncoding = null;
    long bodyCompressedLength = 0;
    String contentEncoding = headers.getOrDefault("content-encoding", "").toLowerCase();
    if (bodyBytes.length > 0 && !contentEncoding.isEmpty()) {
      byte[] result = null;
      if (contentEncoding.contains("gzip")) {
        result = tryDecompressGzip(bodyBytes);
        if (result != null) bodyEncoding = "gzip";
      } else if (contentEncoding.contains("deflate")) {
        result = tryDecompressDeflate(bodyBytes);
        if (result != null) bodyEncoding = "deflate";
      }
      if (result != null) {
        bodyCompressedLength = bodyBytes.length;
        bodyBytes = result;
        actualBodyLength = bodyBytes.length;
        decompressed = true;
      }
    }

    // Truncate for display
    boolean bodyTruncated = bodyBytes.length > MAX_BODY_DISPLAY_BYTES;
    if (bodyTruncated) {
      bodyBytes = Arrays.copyOf(bodyBytes, MAX_BODY_DISPLAY_BYTES);
    }

    boolean binary = bodyBytes.length > 0 && !isPrintableAscii(bodyBytes);
    String bodyText = binary ? null : new String(bodyBytes, StandardCharsets.UTF_8);

    return SessionResponse.HttpMessage.builder()
        .firstLine(firstLine)
        .headers(headers)
        .body(bodyText)
        .bodyBinary(binary)
        .bodyDecompressed(decompressed)
        .bodyEncoding(bodyEncoding)
        .bodyCompressedLength(bodyCompressedLength)
        .bodyTruncated(bodyTruncated)
        .bodyLength(actualBodyLength)
        .build();
  }

  /** Decodes a chunked-encoded body. Returns the raw bytes if decoding fails. */
  private byte[] decodeChunked(byte[] data) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int pos = 0;
    try {
      while (pos < data.length) {
        // Read chunk size line
        int lineEnd = indexOf(data, pos, "\r\n".getBytes(StandardCharsets.US_ASCII));
        if (lineEnd < 0) break;
        String sizeLine =
            new String(Arrays.copyOfRange(data, pos, lineEnd), StandardCharsets.US_ASCII).trim();
        // Strip chunk extensions (e.g. "1a;ext=val")
        int semi = sizeLine.indexOf(';');
        if (semi >= 0) sizeLine = sizeLine.substring(0, semi).trim();
        if (sizeLine.isEmpty()) {
          pos = lineEnd + 2;
          continue;
        }
        int chunkSize = Integer.parseInt(sizeLine, 16);
        if (chunkSize == 0) break;
        pos = lineEnd + 2;
        if (pos + chunkSize > data.length) chunkSize = data.length - pos;
        out.write(data, pos, chunkSize);
        pos += chunkSize + 2; // skip trailing \r\n
      }
      return out.toByteArray();
    } catch (Exception e) {
      return data; // return raw on error
    }
  }

  private byte[] tryDecompressGzip(byte[] data) {
    try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(data))) {
      return gzip.readAllBytes();
    } catch (Exception e) {
      return null;
    }
  }

  private byte[] tryDecompressDeflate(byte[] data) {
    // Try zlib-wrapped deflate first (RFC 7230 recommends this format).
    try (InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(data))) {
      return iis.readAllBytes();
    } catch (Exception e) {
      // Fall back to raw deflate (no zlib wrapper).
      try (InflaterInputStream iis =
          new InflaterInputStream(new ByteArrayInputStream(data), new Inflater(true))) {
        return iis.readAllBytes();
      } catch (Exception e2) {
        return null;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Utility helpers
  // -------------------------------------------------------------------------

  private boolean isPrintableAscii(byte[] data) {
    if (data.length == 0) return true;
    int printable = 0;
    int sample = Math.min(data.length, 512);
    for (int i = 0; i < sample; i++) {
      int b = data[i] & 0xFF;
      if ((b >= 0x20 && b <= 0x7E) || b == '\r' || b == '\n' || b == '\t') {
        printable++;
      }
    }
    return (double) printable / sample > 0.7;
  }

  private String formatHexDump(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < data.length; i += 16) {
      sb.append(String.format("%04x  ", i));
      int end = Math.min(i + 16, data.length);
      for (int j = i; j < end; j++) {
        sb.append(String.format("%02x ", data[j] & 0xFF));
      }
      // Padding
      for (int j = end; j < i + 16; j++) sb.append("   ");
      sb.append(" |");
      for (int j = i; j < end; j++) {
        int b = data[j] & 0xFF;
        sb.append((b >= 0x20 && b <= 0x7E) ? (char) b : '.');
      }
      sb.append("|\n");
    }
    return sb.toString();
  }

  private byte[] hexToBytes(String hex) {
    if (hex == null || hex.isBlank()) return new byte[0];
    int len = hex.length();
    if (len % 2 != 0) {
      // Odd-length hex is malformed — do not silently corrupt the last byte
      return null;
    }
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      try {
        out[i / 2] = (byte) Integer.parseInt(hex, i, i + 2, 16);
      } catch (NumberFormatException e) {
        return null;
      }
    }
    return out;
  }

  private int indexOf(byte[] haystack, byte[] needle) {
    return indexOf(haystack, 0, needle);
  }

  private int indexOf(byte[] haystack, int start, byte[] needle) {
    outer:
    for (int i = start; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) continue outer;
      }
      return i;
    }
    return -1;
  }

  private SessionResponse error(String message) {
    return SessionResponse.builder().errorMessage(message).chunks(List.of()).build();
  }

  // -------------------------------------------------------------------------
  // Inner types
  // -------------------------------------------------------------------------

  private static class StreamLocation {
    final String proto; // "tcp" or "udp"
    final int streamIndex;

    StreamLocation(String proto, int streamIndex) {
      this.proto = proto;
      this.streamIndex = streamIndex;
    }
  }

  private static class RawChunk {
    final String direction;
    final byte[] data;

    RawChunk(String direction, byte[] data) {
      this.direction = direction;
      this.data = data;
    }
  }
}
