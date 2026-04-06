package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.ExtractedFileEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.ExtractedFileRepository;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.service.StorageService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.tika.Tika;
import org.apache.tika.mime.MimeType;
import org.apache.tika.mime.MimeTypeException;
import org.apache.tika.mime.MimeTypes;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Extracts files embedded in packet streams from a PCAP file.
 *
 * <p>Two strategies are used:
 *
 * <ol>
 *   <li>HTTP objects via {@code tshark --export-objects http}
 *   <li>Raw TCP/UDP streams: conversations where packets had file-type detections are reconstructed
 *       and scanned for known magic-byte signatures.
 * </ol>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FileExtractionService {

  /** Maximum size of a single extracted file stored in MinIO (50 MB). */
  private static final int MAX_EXTRACTED_FILE_BYTES = 50 * 1024 * 1024;

  /** Maximum number of non-HTTP conversations to scan for embedded files. */
  private static final int MAX_RAW_STREAM_CONVERSATIONS = 50;

  /**
   * Maximum embedded files extracted per raw stream. Prevents runaway extraction on streams that
   * contain many magic-byte sequences (e.g. synthetic test data or binary protocols).
   */
  private static final int MAX_MATCHES_PER_STREAM = 20;

  private static final Tika TIKA = new Tika();

  /** Tika MIME type repository — used to resolve file extensions from detected MIME strings. */
  private static final MimeTypes TIKA_MIME_REPO = MimeTypes.getDefaultMimeTypes();

  // -------------------------------------------------------------------------
  // Aho-Corasick automaton — built once at class load from MAGIC_PATTERNS
  // -------------------------------------------------------------------------

  /**
   * Known file-format magic byte sequences. Aho-Corasick finds their positions in a stream in one
   * O(n) pass; Tika then confirms each candidate. This replaces the old O(n/4) sliding-window
   * approach and reduces per-stream Tika calls from millions to O(actual matches).
   */
  private static final List<byte[]> MAGIC_PATTERNS = buildMagicPatterns();

  /**
   * Complete Aho-Corasick GOTO table: {@code AC_GOTO[state][byte] = nextState}. "Complete" means
   * failure-link logic is baked in — no −1 entries — so the search loop is a single array lookup
   * per byte with no branching.
   */
  private static final int[][] AC_GOTO;

  /**
   * Output function: {@code AC_OUTPUT[state]} is the index into {@link #MAGIC_PATTERNS} for a
   * terminal state, or −1 for non-terminal states.
   */
  private static final int[] AC_OUTPUT;

  static {
    int totalLen = MAGIC_PATTERNS.stream().mapToInt(p -> p.length).sum();
    int maxStates = totalLen + 1;

    int[][] gotoFn = new int[maxStates][256];
    int[] output = new int[maxStates];
    int[] fail = new int[maxStates];
    Arrays.fill(output, -1);
    for (int[] row : gotoFn) Arrays.fill(row, -1);

    // Phase 1 — insert all patterns into the trie
    int stateCount = 1; // 0 = root
    for (int pi = 0; pi < MAGIC_PATTERNS.size(); pi++) {
      byte[] pat = MAGIC_PATTERNS.get(pi);
      int cur = 0;
      for (byte b : pat) {
        int c = b & 0xFF;
        if (gotoFn[cur][c] == -1) gotoFn[cur][c] = stateCount++;
        cur = gotoFn[cur][c];
      }
      output[cur] = pi;
    }

    // Phase 2 — complete root (missing transitions → root) and BFS failure links
    for (int c = 0; c < 256; c++) {
      if (gotoFn[0][c] == -1) gotoFn[0][c] = 0;
    }
    Queue<Integer> q = new ArrayDeque<>();
    for (int c = 0; c < 256; c++) {
      int s = gotoFn[0][c];
      if (s != 0) {
        fail[s] = 0;
        q.add(s);
      }
    }
    while (!q.isEmpty()) {
      int r = q.poll();
      for (int c = 0; c < 256; c++) {
        int s = gotoFn[r][c];
        if (s == -1) {
          gotoFn[r][c] = gotoFn[fail[r]][c]; // complete: borrow from failure ancestor
        } else {
          fail[s] = gotoFn[fail[r]][c];
          if (output[s] == -1) output[s] = output[fail[s]]; // propagate suffix output
          q.add(s);
        }
      }
    }

    AC_GOTO = Arrays.copyOf(gotoFn, stateCount);
    AC_OUTPUT = Arrays.copyOf(output, stateCount);
  }

  // -------------------------------------------------------------------------
  // Magic byte scanning result
  // -------------------------------------------------------------------------

  /**
   * A confirmed magic-byte match within a byte stream.
   *
   * @param start byte offset where the file signature was detected
   * @param end byte offset of the end of the stream (file data ends here unless truncated)
   * @param mimeType MIME type string detected by Tika
   * @param ext file extension (without leading dot)
   */
  private record MagicMatch(int start, int end, String mimeType, String ext) {}

  /** Associates a tshark stream index with its transport protocol ("tcp" or "udp"). */
  private record StreamInfo(String transport, int index) {}

  @PersistenceContext private EntityManager entityManager;

  private final ExtractedFileRepository extractedFileRepository;
  private final ConversationRepository conversationRepository;
  private final PacketRepository packetRepository;
  private final StorageService storageService;

  // -------------------------------------------------------------------------
  // Public entry point
  // -------------------------------------------------------------------------

  /**
   * Extracts files from the given PCAP and saves metadata to the database.
   *
   * <p>Must be called within the same transaction that saved the conversations so that
   * flushed-but-uncommitted conversation rows are visible to repository queries.
   *
   * @param file the persisted FileEntity
   * @param tempPcapFile the PCAP on local disk (will not be deleted here)
   * @param savedConversationIds IDs of conversations already persisted to DB for this file
   */
  @Transactional
  public void extractFiles(FileEntity file, File tempPcapFile, List<UUID> savedConversationIds) {

    log.info("Starting file extraction for PCAP {}", file.getId());

    // Load all conversations once — shared by both extraction strategies
    List<ConversationEntity> allConvs =
        (savedConversationIds == null || savedConversationIds.isEmpty())
            ? List.of()
            : conversationRepository.findAllById(savedConversationIds);

    try {
      extractHttpObjects(file, tempPcapFile, allConvs);
    } catch (Exception e) {
      log.warn("HTTP object extraction failed for {}: {}", file.getId(), e.getMessage());
    }

    try {
      extractFromRawStreams(file, tempPcapFile, allConvs);
    } catch (Exception e) {
      log.warn("Raw stream extraction failed for {}: {}", file.getId(), e.getMessage());
    }

    log.info("File extraction complete for PCAP {}", file.getId());
  }

  // -------------------------------------------------------------------------
  // HTTP export via tshark --export-objects
  // -------------------------------------------------------------------------

  private void extractHttpObjects(
      FileEntity file, File tempPcapFile, List<ConversationEntity> convs) throws Exception {
    File tmpDir = Files.createTempDirectory("tshark-http-").toFile();
    try {
      ProcessBuilder pb =
          new ProcessBuilder(
              "tshark",
              "-r",
              tempPcapFile.getAbsolutePath(),
              "--export-objects",
              "http," + tmpDir.getAbsolutePath());
      pb.redirectError(ProcessBuilder.Redirect.DISCARD);
      Process proc = pb.start();
      proc.getInputStream().transferTo(OutputStream.nullOutputStream());
      proc.waitFor(60, java.util.concurrent.TimeUnit.SECONDS);

      File[] files = tmpDir.listFiles();
      if (files == null || files.length == 0) {
        log.debug("No HTTP objects found in PCAP {}", file.getId());
        return;
      }

      log.info("tshark exported {} HTTP object(s) from PCAP {}", files.length, file.getId());

      // Build filename → conversationId map via a second tshark pass
      Map<String, UUID> filenameToConvId =
          convs.isEmpty() ? new HashMap<>() : buildHttpFilenameConvMap(tempPcapFile, convs);

      // Fallback: numbered variants like "xcms(1).asp" share the same TCP stream as "xcms.asp"
      // (tshark exports both POST request body and response body under the same basename).
      // If a file has a (N) suffix and its base variant is in the map, use the same conversation.
      for (File f : files) {
        if (!f.isFile()) continue;
        String name = f.getName();
        if (!filenameToConvId.containsKey(name)) {
          String base = stripNumberSuffix(name);
          if (base != null) {
            UUID fallback = filenameToConvId.get(base);
            if (fallback != null) filenameToConvId.put(name, fallback);
          }
        }
      }

      for (File f : files) {
        if (!f.isFile()) continue;
        try {
          UUID convId = filenameToConvId.get(f.getName());
          processLocalFile(file, convId, f, "tshark_http");
        } catch (Exception e) {
          log.warn("Failed to store HTTP object {}: {}", f.getName(), e.getMessage());
        }
      }
    } finally {
      deleteDir(tmpDir);
    }
  }

  /**
   * Runs a secondary tshark pass to correlate exported HTTP filenames with conversation IDs.
   *
   * <p>tshark names exported HTTP objects after the last path segment of the response URI,
   * appending {@code (N)} before the extension when the same basename appears multiple times (e.g.
   * {@code dagbok.html}, {@code dagbok(1).html}, {@code dagbok(2).html}). We replicate this
   * numbering by processing URIs in pcap order and tracking per-basename counts.
   *
   * @return map from tshark-exported filename → conversation UUID
   */
  private Map<String, UUID> buildHttpFilenameConvMap(
      File pcapFile, List<ConversationEntity> convs) {
    Map<String, UUID> result = new HashMap<>();
    // Must track counts in pcap order — LinkedHashMap preserves insertion order
    Map<String, Integer> basenameCount = new LinkedHashMap<>();
    try {
      // Use http.request (one entry per HTTP request) instead of http.response_for.uri
      // (which returns both request AND response packets, causing double-counting of basenames).
      // src = client, dst = server — bidirectional matching handles storage order.
      ProcessBuilder pb =
          new ProcessBuilder(
              "tshark",
              "-r",
              pcapFile.getAbsolutePath(),
              "-Y",
              "http.request",
              "-T",
              "fields",
              "-e",
              "http.request.uri",
              "-e",
              "ip.src",
              "-e",
              "ipv6.src",
              "-e",
              "tcp.srcport",
              "-e",
              "ip.dst",
              "-e",
              "ipv6.dst",
              "-e",
              "tcp.dstport");
      pb.redirectError(ProcessBuilder.Redirect.DISCARD);
      Process proc = pb.start();

      try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
        String line;
        while ((line = br.readLine()) != null) {
          String[] cols = line.split("\t", -1);
          if (cols.length < 7) continue;
          String uri = cols[0].trim();
          String srcIp = firstNonEmpty(cols[1], cols[2]);
          String srcPort = cols[3].trim();
          String dstIp = firstNonEmpty(cols[4], cols[5]);
          String dstPort = cols[6].trim();
          if (uri.isEmpty()) continue;

          // Derive basename and replicate tshark's (N) duplicate-numbering scheme
          String basename = uriToBasename(uri);
          int count = basenameCount.getOrDefault(basename, 0);
          basenameCount.put(basename, count + 1);
          String filename = count == 0 ? basename : addDuplicateSuffix(basename, count);

          if (srcIp == null || dstIp == null) continue;
          Integer sp = parsePort(srcPort);
          Integer dp = parsePort(dstPort);
          ConversationEntity conv = findConvByEndpoints(convs, srcIp, sp, dstIp, dp);
          if (conv != null) {
            result.put(filename, conv.getId());
          }
        }
      }
      proc.waitFor(60, java.util.concurrent.TimeUnit.SECONDS);
    } catch (Exception e) {
      log.debug("HTTP filename→conv map build failed: {}", e.getMessage());
    }
    return result;
  }

  /**
   * Derives the base filename from an HTTP URI the same way tshark does: last path segment,
   * URL-decoded, with unsafe chars replaced by {@code _}. Returns {@code %2f} for root/empty paths
   * (matching tshark's observed behaviour).
   */
  private static String uriToBasename(String uri) {
    try {
      String path = uri;
      int schemeEnd = uri.indexOf("://");
      if (schemeEnd >= 0) {
        int slashAfterHost = uri.indexOf('/', schemeEnd + 3);
        path = slashAfterHost >= 0 ? uri.substring(slashAfterHost) : "/";
      }
      int q = path.indexOf('?');
      if (q >= 0) path = path.substring(0, q);
      int f = path.indexOf('#');
      if (f >= 0) path = path.substring(0, f);
      int lastSlash = path.lastIndexOf('/');
      String segment = lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
      segment = URLDecoder.decode(segment, StandardCharsets.UTF_8);
      segment = segment.replaceAll("[/\\\\:*?\"<>|\t]", "_");
      return segment.isBlank() ? "%2f" : segment;
    } catch (Exception e) {
      return "%2f";
    }
  }

  /**
   * Strips a tshark duplicate-numbering suffix from a filename. e.g. {@code "xcms(1).asp"} → {@code
   * "xcms.asp"}, {@code "dagbok(2).html"} → {@code "dagbok.html"}. Returns {@code null} if the
   * filename has no such suffix.
   */
  private static String stripNumberSuffix(String filename) {
    int dot = filename.lastIndexOf('.');
    String base = dot > 0 ? filename.substring(0, dot) : filename;
    String ext = dot > 0 ? filename.substring(dot) : "";
    int open = base.lastIndexOf('(');
    if (open <= 0 || !base.endsWith(")")) return null;
    String inner = base.substring(open + 1, base.length() - 1);
    try {
      Integer.parseInt(inner);
    } catch (NumberFormatException e) {
      return null;
    }
    return base.substring(0, open) + ext;
  }

  /**
   * Replicates tshark's duplicate-filename suffix: inserts {@code (N)} before the extension. e.g.
   * {@code addDuplicateSuffix("dagbok.html", 1)} → {@code "dagbok(1).html"}.
   */
  private static String addDuplicateSuffix(String basename, int n) {
    int dot = basename.lastIndexOf('.');
    if (dot > 0) {
      return basename.substring(0, dot) + "(" + n + ")" + basename.substring(dot);
    }
    return basename + "(" + n + ")";
  }

  /** Returns the first non-empty, non-null string from the arguments. */
  private static String firstNonEmpty(String a, String b) {
    if (a != null && !a.isBlank()) return a.trim();
    if (b != null && !b.isBlank()) return b.trim();
    return null;
  }

  private static Integer parsePort(String s) {
    if (s == null || s.isBlank()) return null;
    try {
      return Integer.parseInt(s.trim());
    } catch (NumberFormatException e) {
      return null;
    }
  }

  /** Finds a conversation matching the given endpoint pair (bidirectional). */
  private static ConversationEntity findConvByEndpoints(
      List<ConversationEntity> convs,
      String srcIp,
      Integer srcPort,
      String dstIp,
      Integer dstPort) {
    for (ConversationEntity c : convs) {
      boolean fwd =
          eq(c.getSrcIp(), srcIp)
              && eq(c.getDstIp(), dstIp)
              && eq(c.getSrcPort(), srcPort)
              && eq(c.getDstPort(), dstPort);
      boolean rev =
          eq(c.getSrcIp(), dstIp)
              && eq(c.getDstIp(), srcIp)
              && eq(c.getSrcPort(), dstPort)
              && eq(c.getDstPort(), srcPort);
      if (fwd || rev) return c;
    }
    return null;
  }

  private static boolean eq(Object a, Object b) {
    if (a == null && b == null) return true;
    if (a == null || b == null) return false;
    return a.equals(b);
  }

  // -------------------------------------------------------------------------
  // Raw stream extraction
  // -------------------------------------------------------------------------

  private void extractFromRawStreams(
      FileEntity file, File tempPcapFile, List<ConversationEntity> allConvs) {

    if (allConvs.isEmpty()) return;

    List<UUID> allIds = allConvs.stream().map(ConversationEntity::getId).toList();

    // Which conversations had packets with a detected file type?
    List<Object[]> hits = packetRepository.findFileTypesByConversationIds(allIds);
    Set<UUID> convIdsWithFiles =
        hits.stream().map(row -> (UUID) row[0]).collect(Collectors.toSet());

    if (convIdsWithFiles.isEmpty()) return;

    List<ConversationEntity> candidates =
        allConvs.stream()
            .filter(c -> convIdsWithFiles.contains(c.getId()))
            .filter(
                c -> {
                  String tp = c.getTsharkProtocol();
                  return tp == null || !tp.toUpperCase().contains("HTTP");
                })
            .limit(MAX_RAW_STREAM_CONVERSATIONS)
            .toList();

    if (candidates.isEmpty()) return;

    // Single tshark pass to resolve stream indices for all candidate conversations at once.
    Map<String, StreamInfo> streamIndexMap = buildStreamIndexMap(tempPcapFile);

    Map<ConversationEntity, StreamInfo> convStreamMap = new LinkedHashMap<>();
    for (ConversationEntity conv : candidates) {
      StreamInfo info =
          streamIndexMap.get(
              streamKey(conv.getSrcIp(), conv.getSrcPort(), conv.getDstIp(), conv.getDstPort()));
      if (info == null) {
        info =
            streamIndexMap.get(
                streamKey(
                    conv.getDstIp(), conv.getDstPort(),
                    conv.getSrcIp(), conv.getSrcPort()));
      }
      if (info != null) convStreamMap.put(conv, info);
    }

    if (convStreamMap.isEmpty()) return;

    Set<Integer> tcpIds = new HashSet<>(), udpIds = new HashSet<>();
    for (StreamInfo info : convStreamMap.values()) {
      ("tcp".equals(info.transport()) ? tcpIds : udpIds).add(info.index());
    }

    // Single tshark pass to read all required streams at once.
    Map<String, byte[]> streamData = readAllStreams(tempPcapFile, tcpIds, udpIds);

    for (Map.Entry<ConversationEntity, StreamInfo> entry : convStreamMap.entrySet()) {
      ConversationEntity conv = entry.getKey();
      StreamInfo info = entry.getValue();
      byte[] streamBytes = streamData.get(info.transport() + ":" + info.index());
      if (streamBytes == null || streamBytes.length == 0) continue;
      try {
        processMagicMatches(file, conv, streamBytes);
      } catch (Exception e) {
        log.debug(
            "Stream extraction skipped for conversation {}: {}", conv.getId(), e.getMessage());
      }
    }
  }

  private void processMagicMatches(FileEntity file, ConversationEntity conv, byte[] streamBytes) {
    List<MagicMatch> segments = findMagicMatches(streamBytes);
    for (MagicMatch seg : segments) {
      int start = seg.start();
      int end = Math.min(seg.end(), start + MAX_EXTRACTED_FILE_BYTES);
      if (end <= start) continue;
      byte[] fileData = Arrays.copyOfRange(streamBytes, start, end);

      String sha256 = sha256Hex(fileData);
      if (extractedFileRepository.existsByFileIdAndSha256(file.getId(), sha256)) continue;

      String mime = detectMime(fileData);
      String ext = seg.ext();
      String name = "stream-" + conv.getId().toString().substring(0, 8) + "-" + start + "." + ext;
      storeExtractedFile(file, conv.getId(), fileData, name, mime, sha256, "magic_bytes");
    }
  }

  // -------------------------------------------------------------------------
  // Batched stream index lookup — single tshark pass for all conversations
  // -------------------------------------------------------------------------

  /**
   * Reads the pcap once and builds a map from conversation-endpoint key to (transport,
   * streamIndex). Replaces the old per-conversation findStreamIndex calls.
   */
  private Map<String, StreamInfo> buildStreamIndexMap(File pcapFile) {
    Map<String, StreamInfo> map = new HashMap<>();
    try {
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
              "tcp.stream",
              "-e",
              "udp.srcport",
              "-e",
              "udp.dstport",
              "-e",
              "udp.stream");
      pb.redirectError(ProcessBuilder.Redirect.DISCARD);
      Process proc = pb.start();

      try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
        String line;
        while ((line = br.readLine()) != null) {
          String[] f = line.split("\\|", -1);
          if (f.length < 10) continue;

          String srcIp = firstNonEmpty(f[0], f[2]);
          String dstIp = firstNonEmpty(f[1], f[3]);
          if (srcIp == null || dstIp == null) continue;

          // TCP
          if (!f[6].isEmpty()) {
            try {
              int idx = Integer.parseInt(f[6].split(",")[0].trim());
              putBoth(
                  map, srcIp, parsePort(f[4]), dstIp, parsePort(f[5]), new StreamInfo("tcp", idx));
            } catch (NumberFormatException ignored) {
            }
          }

          // UDP
          if (!f[9].isEmpty()) {
            try {
              int idx = Integer.parseInt(f[9].split(",")[0].trim());
              putBoth(
                  map, srcIp, parsePort(f[7]), dstIp, parsePort(f[8]), new StreamInfo("udp", idx));
            } catch (NumberFormatException ignored) {
            }
          }
        }
      }
      if (!proc.waitFor(120, java.util.concurrent.TimeUnit.SECONDS)) {
        proc.destroyForcibly();
      }
    } catch (Exception e) {
      log.warn("buildStreamIndexMap failed: {}", e.getMessage());
    }
    return map;
  }

  private static void putBoth(
      Map<String, StreamInfo> map,
      String srcIp,
      Integer srcPort,
      String dstIp,
      Integer dstPort,
      StreamInfo info) {
    map.putIfAbsent(streamKey(srcIp, srcPort, dstIp, dstPort), info);
    map.putIfAbsent(streamKey(dstIp, dstPort, srcIp, srcPort), info);
  }

  private static String streamKey(String ip1, Integer p1, String ip2, Integer p2) {
    return ip1 + ":" + p1 + "\u2192" + ip2 + ":" + p2;
  }

  // -------------------------------------------------------------------------
  // Batched stream reading — single tshark pass for all streams
  // -------------------------------------------------------------------------

  /**
   * Reads all requested TCP and UDP streams in one tshark invocation using multiple {@code -z
   * follow,<proto>,raw,<N>} arguments. Returns a map from "tcp:N" / "udp:N" to the reassembled raw
   * bytes for that stream.
   */
  private Map<String, byte[]> readAllStreams(
      File pcapFile, Set<Integer> tcpIds, Set<Integer> udpIds) {
    Map<String, byte[]> result = new HashMap<>();
    if (tcpIds.isEmpty() && udpIds.isEmpty()) return result;

    List<String> cmd = new ArrayList<>();
    cmd.add("tshark");
    cmd.add("-r");
    cmd.add(pcapFile.getAbsolutePath());
    cmd.add("-q");
    for (int idx : tcpIds) {
      cmd.add("-z");
      cmd.add("follow,tcp,raw," + idx);
    }
    for (int idx : udpIds) {
      cmd.add("-z");
      cmd.add("follow,udp,raw," + idx);
    }

    try {
      ProcessBuilder pb = new ProcessBuilder(cmd);
      pb.redirectError(ProcessBuilder.Redirect.DISCARD);
      Process proc = pb.start();

      String currentKey = null;
      ByteArrayOutputStream currentBuf = null;

      try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
        String line;
        while ((line = br.readLine()) != null) {
          if (line.startsWith("=====")) {
            // Block delimiter — flush current stream if any
            if (currentKey != null && currentBuf != null) {
              result.put(currentKey, currentBuf.toByteArray());
            }
            currentKey = null;
            currentBuf = null;
          } else if (line.startsWith("Filter: tcp.stream eq ")) {
            currentKey = "tcp:" + line.substring("Filter: tcp.stream eq ".length()).trim();
            currentBuf = new ByteArrayOutputStream();
          } else if (line.startsWith("Filter: udp.stream eq ")) {
            currentKey = "udp:" + line.substring("Filter: udp.stream eq ".length()).trim();
            currentBuf = new ByteArrayOutputStream();
          } else if (currentBuf != null
              && !line.startsWith("Follow:")
              && !line.startsWith("Node ")) {
            String hexLine = line.stripLeading();
            if (!hexLine.isEmpty()) {
              byte[] chunk = hexToBytes(hexLine);
              if (chunk != null && currentBuf.size() + chunk.length <= MAX_EXTRACTED_FILE_BYTES) {
                currentBuf.write(chunk);
              }
            }
          }
        }
        // Flush final stream (no trailing === in some tshark versions)
        if (currentKey != null && currentBuf != null) {
          result.put(currentKey, currentBuf.toByteArray());
        }
      }
      if (!proc.waitFor(300, java.util.concurrent.TimeUnit.SECONDS)) {
        proc.destroyForcibly();
      }
    } catch (Exception e) {
      log.warn("readAllStreams failed: {}", e.getMessage());
    }
    return result;
  }

  private static byte[] hexToBytes(String hex) {
    if (hex == null || hex.length() % 2 != 0) return null;
    for (char c : hex.toCharArray()) {
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
        return null;
    }
    byte[] out = new byte[hex.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Magic byte scanning (Aho-Corasick + Tika confirmation)
  // -------------------------------------------------------------------------

  /**
   * Scans {@code data} for embedded files using Aho-Corasick to locate magic-byte candidates in one
   * O(n) pass, then confirms each with a single Tika call.
   *
   * <p>This replaces the old sliding-window approach (O(n/4) Tika calls) and reduces per-stream
   * Tika invocations from millions to O(actual magic-byte matches) — roughly 100–500× fewer calls
   * on large streams with few or no embedded files.
   */
  private List<MagicMatch> findMagicMatches(byte[] data) {
    List<MagicMatch> results = new ArrayList<>();
    int state = 0;
    int i = 0;
    while (i < data.length) {
      state = AC_GOTO[state][data[i] & 0xFF];
      i++;
      int pi = AC_OUTPUT[state];
      if (pi < 0) continue;

      int patLen = MAGIC_PATTERNS.get(pi).length;
      int start = i - patLen;
      if (start < 0) continue;

      // Tika confirmation — only called at actual magic-byte positions
      int windowEnd = Math.min(start + 32, data.length);
      String mime = detectMime(Arrays.copyOfRange(data, start, windowEnd));
      if ("application/octet-stream".equals(mime) || "text/plain".equals(mime)) continue;

      String ext;
      try {
        MimeType mt = TIKA_MIME_REPO.forName(mime);
        ext = mt.getExtension();
        if (ext.startsWith(".")) ext = ext.substring(1);
      } catch (MimeTypeException e) {
        ext = mime.contains("/") ? mime.substring(mime.lastIndexOf('/') + 1) : "bin";
      }
      if (ext.isEmpty()) ext = "bin";

      results.add(new MagicMatch(start, data.length, mime, ext));
      if (results.size() >= MAX_MATCHES_PER_STREAM) break;
      // Jump past this match's signature region to avoid re-detecting the same file body,
      // then reset the automaton so it starts fresh from the new position.
      i = start + 256;
      state = 0;
    }
    return results;
  }

  /**
   * Magic byte sequences searched by the Aho-Corasick automaton. Covers archives, documents,
   * images, audio/video, executables, crypto, and common text formats.
   */
  private static List<byte[]> buildMagicPatterns() {
    List<byte[]> p = new ArrayList<>();
    // Archives
    add(p, 0x50, 0x4B, 0x03, 0x04); // ZIP / OOXML / JAR / APK
    add(p, 0x50, 0x4B, 0x05, 0x06); // ZIP (empty)
    add(p, 0x50, 0x4B, 0x07, 0x08); // ZIP (spanned)
    add(p, 0x1F, 0x8B); // GZIP
    add(p, 0x42, 0x5A, 0x68); // BZIP2
    add(p, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C); // 7-Zip
    add(p, 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07); // RAR v4
    add(p, 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00); // XZ
    add(p, 0x28, 0xB5, 0x2F, 0xFD); // Zstandard
    add(p, 0x60, 0xEA); // ARJ
    add(p, 0x30, 0x37, 0x30, 0x37, 0x30, 0x31); // CPIO new ASCII (070701)
    add(p, 0x30, 0x37, 0x30, 0x37, 0x30, 0x32); // CPIO new CRC  (070702)
    add(p, 0xC7, 0x71); // CPIO binary
    add(p, 0x71, 0xC7); // CPIO binary (BE)
    // Documents
    add(p, 0x25, 0x50, 0x44, 0x46); // PDF
    add(p, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1); // OLE2 (DOC / XLS / PPT)
    add(p, 0x7B, 0x5C, 0x72, 0x74, 0x66); // RTF
    add(p, 0x25, 0x21); // PostScript
    // Images
    add(p, 0xFF, 0xD8, 0xFF); // JPEG
    add(p, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A); // PNG
    add(p, 0x47, 0x49, 0x46, 0x38, 0x37, 0x61); // GIF87a
    add(p, 0x47, 0x49, 0x46, 0x38, 0x39, 0x61); // GIF89a
    add(p, 0x42, 0x4D); // BMP
    add(p, 0x49, 0x49, 0x2A, 0x00); // TIFF LE
    add(p, 0x4D, 0x4D, 0x00, 0x2A); // TIFF BE
    add(p, 0x52, 0x49, 0x46, 0x46); // RIFF (WAV / AVI / WebP)
    add(p, 0x00, 0x00, 0x01, 0x00); // ICO
    add(p, 0x0A, 0x05); // PCX v5
    add(p, 0x0A, 0x03); // PCX v3
    add(p, 0x0A, 0x02); // PCX v2
    add(p, 0x38, 0x42, 0x50, 0x53); // Photoshop PSD
    add(p, 0xFF, 0x0A); // JPEG XL codestream
    add(p, 0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20); // JPEG XL ISO box
    // Audio / Video
    add(p, 0xFF, 0xFB); // MP3 (MPEG-1 L3)
    add(p, 0xFF, 0xFA); // MP3 (MPEG-1 L3 protected)
    add(p, 0xFF, 0xF3); // MP3 (MPEG-2 L3)
    add(p, 0xFF, 0xF2); // MP3 (MPEG-2.5 L3)
    add(p, 0x49, 0x44, 0x33); // MP3 ID3 tag
    add(p, 0x0B, 0x77); // AC3 / Dolby Digital
    add(p, 0x66, 0x4C, 0x61, 0x43); // FLAC
    add(p, 0x4F, 0x67, 0x67, 0x53); // OGG
    add(p, 0x1A, 0x45, 0xDF, 0xA3); // MKV / WebM
    add(p, 0x4D, 0x54, 0x68, 0x64); // MIDI
    // Executables
    add(p, 0x7F, 0x45, 0x4C, 0x46); // ELF
    add(p, 0x4D, 0x5A); // PE (EXE / DLL)
    add(p, 0xCA, 0xFE, 0xBA, 0xBE); // Java class / Mach-O fat
    add(p, 0xCE, 0xFA, 0xED, 0xFE); // Mach-O 32-bit LE
    add(p, 0xCF, 0xFA, 0xED, 0xFE); // Mach-O 64-bit LE
    add(p, 0xFE, 0xED, 0xFA, 0xCE); // Mach-O 32-bit BE
    add(p, 0xFE, 0xED, 0xFA, 0xCF); // Mach-O 64-bit BE
    // Crypto / certificates
    add(p, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D); // PEM (-----)
    add(p, 0x30, 0x82); // DER / ASN.1 / PKCS
    // Database
    add(
        p, 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33,
        0x00); // SQLite 3
    // Flash
    add(p, 0x46, 0x57, 0x53); // SWF (FWS)
    add(p, 0x43, 0x57, 0x53); // SWF compressed (CWS)
    add(p, 0x5A, 0x57, 0x53); // SWF LZMA (ZWS)
    // Text / markup
    add(p, 0x3C, 0x3F, 0x78, 0x6D, 0x6C); // <?xml
    add(p, 0x3C, 0x68, 0x74, 0x6D, 0x6C); // <html
    add(p, 0x3C, 0x48, 0x54, 0x4D, 0x4C); // <HTML
    add(p, 0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54); // <!DOCTYPE
    return Collections.unmodifiableList(p);
  }

  /** Packs vararg ints into a {@code byte[]} and appends it to {@code list}. */
  private static void add(List<byte[]> list, int... bytes) {
    byte[] arr = new byte[bytes.length];
    for (int i = 0; i < bytes.length; i++) arr[i] = (byte) bytes[i];
    list.add(arr);
  }

  // -------------------------------------------------------------------------
  // File handling helpers
  // -------------------------------------------------------------------------

  private void processLocalFile(FileEntity file, UUID conversationId, File localFile, String method)
      throws Exception {
    byte[] data = Files.readAllBytes(localFile.toPath());
    if (data.length == 0) return;
    if (data.length > MAX_EXTRACTED_FILE_BYTES) {
      data = Arrays.copyOf(data, MAX_EXTRACTED_FILE_BYTES);
    }
    String sha256 = sha256Hex(data);
    if (extractedFileRepository.existsByFileIdAndSha256(file.getId(), sha256)) return;

    String mime = detectMime(data);
    storeExtractedFile(file, conversationId, data, localFile.getName(), mime, sha256, method);
  }

  private void storeExtractedFile(
      FileEntity file,
      UUID conversationId,
      byte[] data,
      String filename,
      String mimeType,
      String sha256,
      String method) {

    String minioPath =
        String.format("extracted/%s/%s/%s", file.getId(), UUID.randomUUID(), sanitize(filename));

    storageService.uploadBytes(data, minioPath, mimeType);

    // Use getReference so we only set the FK without loading the full entity
    ConversationEntity convRef =
        conversationId != null
            ? entityManager.getReference(ConversationEntity.class, conversationId)
            : null;

    ExtractedFileEntity entity =
        ExtractedFileEntity.builder()
            .file(file)
            .conversation(convRef)
            .filename(filename)
            .mimeType(mimeType)
            .fileSize((long) data.length)
            .sha256(sha256)
            .minioPath(minioPath)
            .extractionMethod(method)
            .build();

    extractedFileRepository.save(entity);
    log.info("Stored extracted file: {} ({} bytes, sha256={})", filename, data.length, sha256);
  }

  // -------------------------------------------------------------------------
  // Utility helpers
  // -------------------------------------------------------------------------

  private String detectMime(byte[] data) {
    try {
      return TIKA.detect(data);
    } catch (Exception e) {
      return "application/octet-stream";
    }
  }

  private static String sha256Hex(byte[] data) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] digest = md.digest(data);
      StringBuilder sb = new StringBuilder(64);
      for (byte b : digest) sb.append(String.format("%02x", b));
      return sb.toString();
    } catch (Exception e) {
      return "unknown";
    }
  }

  private static String sanitize(String name) {
    if (name == null || name.isBlank()) return "file.bin";
    return name.replaceAll("[/\\\\:*?\"<>|]", "_");
  }

  private static void deleteDir(File dir) {
    if (dir == null) return;
    File[] children = dir.listFiles();
    if (children != null) {
      for (File child : children) {
        if (child.isDirectory()) deleteDir(child);
        else child.delete();
      }
    }
    dir.delete();
  }
}
