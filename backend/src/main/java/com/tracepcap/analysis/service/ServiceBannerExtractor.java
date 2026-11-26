package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.ServiceBannerEntity;
import com.tracepcap.analysis.repository.ServiceBannerRepository;
import com.tracepcap.analysis.spi.HostServiceLogExtractor;
import com.tracepcap.analysis.spi.HostServiceLogResult;
import com.tracepcap.analysis.spi.ServiceBannerLookup;
import com.tracepcap.file.entity.FileEntity;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Records what each server said about itself (investigation framework phase 4): its SSH, FTP, HTTP,
 * SMB and MySQL banners, the HASSH of its SSH key exchange, and the initial TTL of its SYN-ACKs.
 * These are what give a stock honeypot away (docs/architecture/investigation-framework.rst,
 * "Honeypots"); the judgment is the knowledge layer's, against the bundled signature file.
 *
 * <p>One read-only tshark pass. Only the server side of a connection counts: the address and port
 * that sent the SYN-ACK, or, for a connection already open when the capture began, the lower port.
 * Degrades quietly: no tshark, or a failed pass, records nothing.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ServiceBannerExtractor implements HostServiceLogExtractor, ServiceBannerLookup {

  /** At most this many distinct (server, port, kind, value) rows per capture. */
  static final int MAX_ROWS = 5_000;

  static final int VALUE_MAX = 255;

  private static final String FILTER =
      "(tcp.flags.syn==1 && tcp.flags.ack==1) || ssh.protocol || ssh.kex.hasshserver"
          + " || ftp.response.code==220 || http.server || smb.native_os || smb.server || mysql.version";

  /** The fields, in the order {@link Tally#accept} reads them. */
  static final String[] FIELDS = {
    "ip.src", "ipv6.src", "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack", "ip.ttl",
    "ipv6.hlim", "ssh.protocol", "ssh.kex.hasshserver", "ftp.response.code", "ftp.response.arg",
    "http.server", "smb.native_os", "smb.native_lanman", "smb.server", "mysql.version", "ip.dst",
    "ipv6.dst"
  };

  private final ServiceBannerRepository repository;
  private final Writer writer;

  @Override
  public String role() {
    return "banner";
  }

  @Override
  public HostServiceLogResult extractAndPersist(FileEntity file, File pcap) {
    Tally tally = new Tally();
    run(pcap, tally);
    List<Banner> banners = tally.banners();
    try {
      writer.replace(file.getId(), banners);
    } catch (Exception e) {
      log.warn("Failed to persist {} service banner row(s): {}", banners.size(), e.getMessage());
    }
    log.info("Service banners: {} row(s) from {} server(s)", banners.size(),
        banners.stream().map(Banner::ip).distinct().count());
    // Banners feed the knowledge layer, not device classification: no roles, no suspicions.
    return HostServiceLogResult.empty();
  }

  @Override
  @Transactional(readOnly = true)
  public List<Banner> banners(UUID fileId) {
    return repository.findByFileId(fileId).stream()
        .map(e -> new Banner(e.getServerIp(), e.getPort(), e.getKind(), e.getValue(), e.getSeenCount()))
        .toList();
  }

  /**
   * Persists a file's banners. Its own bean so the transaction applies (a call from the extractor
   * to itself would skip the proxy), REQUIRES_NEW so a failure rolls back only this write.
   */
  @Service
  @RequiredArgsConstructor
  public static class Writer {
    private final ServiceBannerRepository repository;

    /** Regenerates this file's rows: re-analysis re-derives the same observations. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void replace(UUID fileId, List<Banner> banners) {
      repository.deleteByFileId(fileId);
      if (banners.isEmpty()) return;
      repository.saveAll(banners.stream()
          .map(b -> ServiceBannerEntity.builder().fileId(fileId).serverIp(b.ip()).port(b.port())
              .kind(b.kind()).value(b.value()).seenCount(b.count()).build())
          .toList());
    }
  }

  // ── The pass ──────────────────────────────────────────────────────────────────────────────

  /** Accumulates one capture's banners from tshark's rows, in frame order. */
  static final class Tally {
    /** (ip, port) pairs that sent a SYN-ACK: the server side of a connection. */
    private final Set<String> servers = new HashSet<>();
    private final Map<String, int[]> counts = new LinkedHashMap<>();
    private final Map<String, Integer> ttl = new LinkedHashMap<>();

    synchronized void accept(String[] f) {
      if (f.length < FIELDS.length) return;
      String ip = first(f[0]) != null ? first(f[0]) : first(f[1]);
      Integer port = integer(f[2]), peerPort = integer(f[3]);
      if (ip == null || port == null) return;
      String at = ip + "|" + port;
      boolean synAck = truthy(f[4]) && truthy(f[5]);
      if (synAck) {
        servers.add(at);
        Integer observed = integer(first(f[6]) != null ? f[6] : f[7]);
        if (observed != null) ttl.merge(at, initialTtl(observed), Math::max);
        return;
      }
      // Which side sent it. Known from the handshake when it was captured: the side that sent the
      // SYN-ACK serves, the other is the client. The peer's own address with its port, not ours: a
      // host can serve on one connection and be the client on another.
      String peer = first(f[17]) != null ? first(f[17]) : first(f[18]);
      boolean peerServes = peer != null && peerPort != null && servers.contains(peer + "|" + peerPort);
      boolean knownServer = servers.contains(at);
      boolean knownClient = peerServes && !knownServer;
      if (knownClient) return;
      // Fields only a server sends count whenever the sender isn't known to be the client: a
      // server on a high port can talk to a client on a lower one.
      add(ip, port, "ssh-hassh", f[9]);
      if ("220".equals(first(f[10]))) add(ip, port, "ftp-banner", f[11]);
      add(ip, port, "http-server", f[12]);
      add(ip, port, "smb-server-name", f[15]);
      add(ip, port, "mysql-version", f[16]);
      // Both sides send an SSH version string and an SMB native OS: without a handshake, the lower
      // port is taken as the server's.
      if (!knownServer && (peerPort == null || port >= peerPort)) return;
      add(ip, port, "ssh-banner", f[8]);
      String os = first(f[13]), lanman = first(f[14]);
      if (os != null || lanman != null) {
        add(ip, port, "smb-os", (os == null ? "" : os) + " / " + (lanman == null ? "" : lanman));
      }
    }

    private void add(String ip, int port, String kind, String raw) {
      String value = first(raw);
      if (value == null) return;
      if (value.length() > VALUE_MAX) value = value.substring(0, VALUE_MAX);
      String key = ip + "|" + port + "|" + kind + "|" + value;
      int[] n = counts.get(key);
      if (n != null) n[0]++;
      else if (counts.size() < MAX_ROWS) counts.put(key, new int[] {1});
    }

    synchronized List<Banner> banners() {
      List<Banner> out = new ArrayList<>();
      counts.forEach((key, n) -> {
        String[] k = key.split("\\|", 4);
        out.add(new Banner(k[0], Integer.parseInt(k[1]), k[2], k[3], n[0]));
      });
      ttl.forEach((at, t) -> {
        String[] k = at.split("\\|", 2);
        if (out.size() < MAX_ROWS) out.add(new Banner(k[0], Integer.parseInt(k[1]), "ttl", t.toString(), 1));
      });
      return out;
    }
  }

  /** The initial TTL a stack sent with, from the one seen after some hops: 32, 64, 128 or 255. */
  static int initialTtl(int observed) {
    if (observed <= 32) return 32;
    if (observed <= 64) return 64;
    if (observed <= 128) return 128;
    return 255;
  }

  private static String first(String raw) {
    if (raw == null) return null;
    String v = raw.split(",", 2)[0].strip();
    return v.isEmpty() ? null : v;
  }

  private static Integer integer(String raw) {
    String v = first(raw);
    if (v == null) return null;
    try {
      return Integer.parseInt(v);
    } catch (NumberFormatException e) {
      return null;
    }
  }

  private static boolean truthy(String raw) {
    String v = first(raw);
    return "1".equals(v) || "True".equalsIgnoreCase(v);
  }

  private static void run(File pcap, Tally tally) {
    // Cowrie listens on 2222 and 2223 and is often exposed there directly; tshark 3.6 only knows
    // SSH on 22, so without these its banner on 2222 goes unread.
    List<String> cmd = new ArrayList<>(List.of("tshark", "-r", pcap.getAbsolutePath(),
        "-d", "tcp.port==2222,ssh", "-d", "tcp.port==2223,telnet", "-Y", FILTER,
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"));
    for (String field : FIELDS) {
      cmd.add("-e");
      cmd.add(field);
    }
    Process process = null;
    java.util.concurrent.ExecutorService reader = null;
    try {
      process = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.DISCARD).start();
      final Process proc = process;
      // Rows are read on their own thread, so the timeout below bounds the pass: read on this one,
      // a stalled tshark would hold the analysis until it exits.
      reader = java.util.concurrent.Executors.newSingleThreadExecutor();
      java.util.concurrent.Future<?> rows = reader.submit(() -> {
        try (BufferedReader r = new BufferedReader(
            new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
          String line;
          while ((line = r.readLine()) != null) {
            if (!line.isEmpty()) tally.accept(line.split("\t", -1));
          }
        }
        return null;
      });
      if (!process.waitFor(2, TimeUnit.MINUTES)) {
        log.warn("Service banner pass timed out; keeping what it read");
        process.destroyForcibly();
      }
      try {
        rows.get(30, TimeUnit.SECONDS);
      } catch (java.util.concurrent.TimeoutException e) {
        log.warn("Service banner rows not drained; keeping what was read");
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      log.warn("Service banner pass failed: {}", e.getMessage());
    } finally {
      if (process != null) process.destroyForcibly();
      if (reader != null) reader.shutdownNow();
    }
  }
}
