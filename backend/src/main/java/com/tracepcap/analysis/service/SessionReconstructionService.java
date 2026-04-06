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

    return SessionResponse.builder()
        .detectedProtocol(detectedProtocol)
        .chunks(chunks)
        .httpExchanges(httpExchanges)
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
    }
    String app = conv.getAppName();
    if (app != null) {
      String upper = app.toUpperCase();
      if (upper.contains("HTTP")) return "HTTP";
      if (upper.contains("TLS") || upper.contains("SSL")) return "TLS";
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

    // Handle gzip/deflate
    boolean decompressed = false;
    String contentEncoding = headers.getOrDefault("content-encoding", "");
    if (contentEncoding.toLowerCase().contains("gzip") && bodyBytes.length > 0) {
      byte[] decompressed_ = tryDecompress(bodyBytes);
      if (decompressed_ != null) {
        bodyBytes = decompressed_;
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

  private byte[] tryDecompress(byte[] data) {
    try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(data))) {
      return gzip.readAllBytes();
    } catch (Exception e) {
      return null;
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
