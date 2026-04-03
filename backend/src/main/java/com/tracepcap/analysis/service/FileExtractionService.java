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
 * <ol>
 *   <li>HTTP objects via {@code tshark --export-objects http}</li>
 *   <li>Raw TCP/UDP streams: conversations where packets had file-type detections are
 *       reconstructed and scanned for known magic-byte signatures.</li>
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

  private static final Tika TIKA = new Tika();

  /** Tika MIME type repository — used to resolve file extensions from detected MIME strings. */
  private static final MimeTypes TIKA_MIME_REPO = MimeTypes.getDefaultMimeTypes();

  // -------------------------------------------------------------------------
  // Magic byte scanning result
  // -------------------------------------------------------------------------

  /**
   * A confirmed magic-byte match within a byte stream.
   *
   * @param start    byte offset where the file signature was detected
   * @param end      byte offset of the end of the stream (file data ends here unless truncated)
   * @param mimeType MIME type string detected by Tika
   * @param ext      file extension (without leading dot)
   */
  private record MagicMatch(int start, int end, String mimeType, String ext) {}

  @PersistenceContext
  private EntityManager entityManager;

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
   * <p>Must be called within the same transaction that saved the conversations so
   * that flushed-but-uncommitted conversation rows are visible to repository queries.
   *
   * @param file               the persisted FileEntity
   * @param tempPcapFile       the PCAP on local disk (will not be deleted here)
   * @param savedConversationIds IDs of conversations already persisted to DB for this file
   */
  @Transactional
  public void extractFiles(
      FileEntity file,
      File tempPcapFile,
      List<UUID> savedConversationIds) {

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
              "-r", tempPcapFile.getAbsolutePath(),
              "--export-objects", "http," + tmpDir.getAbsolutePath());
      pb.redirectError(ProcessBuilder.Redirect.DISCARD);
      Process proc = pb.start();
      proc.getInputStream().transferTo(OutputStream.nullOutputStream());
      proc.waitFor();

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
   * appending {@code (N)} before the extension when the same basename appears multiple times
   * (e.g. {@code dagbok.html}, {@code dagbok(1).html}, {@code dagbok(2).html}).
   * We replicate this numbering by processing URIs in pcap order and tracking per-basename counts.
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
              "-r", pcapFile.getAbsolutePath(),
              "-Y", "http.request",
              "-T", "fields",
              "-e", "http.request.uri",
              "-e", "ip.src",
              "-e", "ipv6.src",
              "-e", "tcp.srcport",
              "-e", "ip.dst",
              "-e", "ipv6.dst",
              "-e", "tcp.dstport");
      pb.redirectError(ProcessBuilder.Redirect.DISCARD);
      Process proc = pb.start();

      try (BufferedReader br =
          new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
        String line;
        while ((line = br.readLine()) != null) {
          String[] cols = line.split("\t", -1);
          if (cols.length < 7) continue;
          String uri     = cols[0].trim();
          String srcIp   = firstNonEmpty(cols[1], cols[2]);
          String srcPort = cols[3].trim();
          String dstIp   = firstNonEmpty(cols[4], cols[5]);
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
      proc.waitFor();
    } catch (Exception e) {
      log.debug("HTTP filename→conv map build failed: {}", e.getMessage());
    }
    return result;
  }

  /**
   * Derives the base filename from an HTTP URI the same way tshark does:
   * last path segment, URL-decoded, with unsafe chars replaced by {@code _}.
   * Returns {@code %2f} for root/empty paths (matching tshark's observed behaviour).
   */
  private static String uriToBasename(String uri) {
    try {
      String path = uri;
      int schemeEnd = uri.indexOf("://");
      if (schemeEnd >= 0) {
        int slashAfterHost = uri.indexOf('/', schemeEnd + 3);
        path = slashAfterHost >= 0 ? uri.substring(slashAfterHost) : "/";
      }
      int q = path.indexOf('?'); if (q >= 0) path = path.substring(0, q);
      int f = path.indexOf('#'); if (f >= 0) path = path.substring(0, f);
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
   * Strips a tshark duplicate-numbering suffix from a filename.
   * e.g. {@code "xcms(1).asp"} → {@code "xcms.asp"}, {@code "dagbok(2).html"} → {@code "dagbok.html"}.
   * Returns {@code null} if the filename has no such suffix.
   */
  private static String stripNumberSuffix(String filename) {
    int dot = filename.lastIndexOf('.');
    String base = dot > 0 ? filename.substring(0, dot) : filename;
    String ext  = dot > 0 ? filename.substring(dot) : "";
    int open = base.lastIndexOf('(');
    if (open <= 0 || !base.endsWith(")")) return null;
    String inner = base.substring(open + 1, base.length() - 1);
    try { Integer.parseInt(inner); } catch (NumberFormatException e) { return null; }
    return base.substring(0, open) + ext;
  }

  /**
   * Replicates tshark's duplicate-filename suffix: inserts {@code (N)} before the extension.
   * e.g. {@code addDuplicateSuffix("dagbok.html", 1)} → {@code "dagbok(1).html"}.
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
    try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return null; }
  }

  /** Finds a conversation matching the given endpoint pair (bidirectional). */
  private static ConversationEntity findConvByEndpoints(
      List<ConversationEntity> convs,
      String srcIp, Integer srcPort,
      String dstIp, Integer dstPort) {
    for (ConversationEntity c : convs) {
      boolean fwd =
          eq(c.getSrcIp(), srcIp) && eq(c.getDstIp(), dstIp)
              && eq(c.getSrcPort(), srcPort) && eq(c.getDstPort(), dstPort);
      boolean rev =
          eq(c.getSrcIp(), dstIp) && eq(c.getDstIp(), srcIp)
              && eq(c.getSrcPort(), dstPort) && eq(c.getDstPort(), srcPort);
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
      FileEntity file,
      File tempPcapFile,
      List<ConversationEntity> allConvs) {

    if (allConvs.isEmpty()) return;

    List<UUID> allIds = allConvs.stream().map(ConversationEntity::getId).toList();

    // Which conversations had packets with a detected file type?
    List<Object[]> hits = packetRepository.findFileTypesByConversationIds(allIds);
    Set<UUID> convIdsWithFiles =
        hits.stream().map(row -> (UUID) row[0]).collect(Collectors.toSet());

    if (convIdsWithFiles.isEmpty()) return;

    List<ConversationEntity> candidates =
        allConvs.stream().filter(c -> convIdsWithFiles.contains(c.getId())).toList();

    int processed = 0;
    for (ConversationEntity conv : candidates) {
      if (processed >= MAX_RAW_STREAM_CONVERSATIONS) break;

      // HTTP is handled by tshark --export-objects
      String tproto = conv.getTsharkProtocol();
      if (tproto != null && tproto.toUpperCase().contains("HTTP")) continue;

      try {
        extractFromConversation(file, tempPcapFile, conv);
        processed++;
      } catch (Exception e) {
        log.debug("Stream extraction skipped for conversation {}: {}", conv.getId(), e.getMessage());
      }
    }
  }

  private void extractFromConversation(
      FileEntity file, File tempPcapFile, ConversationEntity conv) throws Exception {

    String transport = null;
    Integer streamIdx = null;
    for (String t : new String[]{"tcp", "udp"}) {
      streamIdx = findStreamIndex(tempPcapFile, conv, t);
      if (streamIdx != null) {
        transport = t;
        break;
      }
    }
    if (transport == null) {
      log.debug("Stream not found for conversation {}", conv.getId());
      return;
    }

    byte[] streamBytes = readFollowRaw(tempPcapFile, transport, streamIdx);
    if (streamBytes == null || streamBytes.length == 0) return;

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
  // Stream index lookup
  // -------------------------------------------------------------------------

  private Integer findStreamIndex(File pcapFile, ConversationEntity conv, String transport)
      throws Exception {
    for (int flip = 0; flip < 2; flip++) {
      String src = flip == 0 ? conv.getSrcIp() : conv.getDstIp();
      String dst = flip == 0 ? conv.getDstIp() : conv.getSrcIp();
      Integer sp = flip == 0 ? conv.getSrcPort() : conv.getDstPort();
      Integer dp = flip == 0 ? conv.getDstPort() : conv.getSrcPort();

      String ipProto = (src != null && src.contains(":")) ? "ipv6" : "ip";
      StringBuilder filter = new StringBuilder();
      filter.append(ipProto).append(".src==").append(src);
      if (sp != null) filter.append(" && ").append(transport).append(".srcport==").append(sp);
      filter.append(" && ").append(ipProto).append(".dst==").append(dst);
      if (dp != null) filter.append(" && ").append(transport).append(".dstport==").append(dp);

      ProcessBuilder pb =
          new ProcessBuilder(
              "tshark",
              "-r", pcapFile.getAbsolutePath(),
              "-Y", filter.toString(),
              "-T", "fields",
              "-e", transport + ".stream");
      pb.redirectError(ProcessBuilder.Redirect.DISCARD);
      Process proc = pb.start();

      try (BufferedReader br =
          new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
        String line;
        while ((line = br.readLine()) != null) {
          line = line.trim();
          if (!line.isEmpty()) {
            try {
              int idx = Integer.parseInt(line);
              proc.destroy();
              return idx;
            } catch (NumberFormatException ignored) {
            }
          }
        }
      }
      proc.waitFor();
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // tshark follow raw → byte[]
  // -------------------------------------------------------------------------

  private byte[] readFollowRaw(File pcapFile, String transport, int streamIdx) throws Exception {
    ProcessBuilder pb =
        new ProcessBuilder(
            "tshark",
            "-r", pcapFile.getAbsolutePath(),
            "-q",
            "-z", "follow," + transport + ",raw," + streamIdx);
    pb.redirectError(ProcessBuilder.Redirect.DISCARD);
    Process proc = pb.start();

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (BufferedReader br =
        new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
      String line;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("===") || line.startsWith("Filter:") || line.startsWith("Node"))
          continue;
        String hexLine = line.stripLeading();
        if (hexLine.isEmpty()) continue;
        byte[] chunk = hexToBytes(hexLine);
        if (chunk != null) {
          bos.write(chunk);
          if (bos.size() >= MAX_EXTRACTED_FILE_BYTES) break;
        }
      }
    }
    proc.waitFor();
    return bos.toByteArray();
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
  // Magic byte scanning (Tika-driven sliding window)
  // -------------------------------------------------------------------------

  /**
   * Scans {@code data} for embedded files using Tika's {@code detect(byte[])} on a sliding window.
   *
   * <p>At each byte position a 32-byte window is passed to Tika. If Tika returns anything other
   * than {@code application/octet-stream} or {@code text/plain}, that position is recorded as the
   * start of an embedded file and the scanner skips forward to avoid re-detecting the same region.
   *
   * <p>This approach is authoritative (uses Tika's full magic database) and requires no upfront
   * probe phase — it correctly handles multi-byte magic patterns at any offset.
   */
  private List<MagicMatch> findMagicMatches(byte[] data) {
    List<MagicMatch> results = new ArrayList<>();
    // Reuse a fixed-size window buffer to avoid per-position allocation.
    byte[] window = new byte[32];
    for (int i = 0; i < data.length; i++) {
      int windowLen = Math.min(32, data.length - i);
      System.arraycopy(data, i, window, 0, windowLen);
      if (windowLen < 32) Arrays.fill(window, windowLen, 32, (byte) 0);

      String mime;
      try {
        mime = TIKA.detect(window);
      } catch (Exception ignored) {
        continue;
      }
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

      results.add(new MagicMatch(i, data.length, mime, ext));
      i += 255; // skip forward — the next file cannot start within the current signature region
    }
    return results;
  }

  // -------------------------------------------------------------------------
  // File handling helpers
  // -------------------------------------------------------------------------

  private void processLocalFile(
      FileEntity file, UUID conversationId, File localFile, String method) throws Exception {
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
