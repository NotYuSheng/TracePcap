package com.tracepcap.analysis.service.hostlog;

import com.tracepcap.analysis.entity.DnsQueryLogEntity;
import com.tracepcap.analysis.repository.DnsQueryLogRepository;
import com.tracepcap.file.entity.FileEntity;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Extracts the DNS query log for hosts acting as DNS servers (#362) — the first implementation of
 * {@link HostServiceLogExtractor}.
 *
 * <p>Runs a single read-only tshark pass over the capture, selecting DNS <em>responses</em>, and
 * aggregates them per {@code (serverIp, queryName, queryType)} into {@link DnsQueryLogEntity} rows:
 * how many times each domain was queried, the response code, the resolved IPs, and whether it
 * resolved. It also tracks each server's share of NXDOMAIN responses and flags servers whose ratio
 * exceeds {@code tracepcap.dns.nxdomain-suspicious-ratio} (over at least
 * {@code tracepcap.dns.nxdomain-min-queries} queries) as suspicious — a signal of DNS tunnelling or
 * a domain-generation algorithm.
 *
 * <p>Degrades gracefully and never throws: on any failure it persists whatever it parsed and
 * returns the suspicions computed so far (possibly empty).
 */
@Slf4j
@Service
public class DnsQueryLogExtractor implements HostServiceLogExtractor {

  public static final String ROLE = "dns";

  private static final int QUERY_NAME_MAX_LENGTH = 255;

  /** DNS QTYPE numeric → name, for the common types we want to display. */
  private static final Map<String, String> QTYPE_NAMES =
      Map.ofEntries(
          Map.entry("1", "A"),
          Map.entry("2", "NS"),
          Map.entry("5", "CNAME"),
          Map.entry("6", "SOA"),
          Map.entry("12", "PTR"),
          Map.entry("15", "MX"),
          Map.entry("16", "TXT"),
          Map.entry("28", "AAAA"),
          Map.entry("33", "SRV"),
          Map.entry("43", "DS"),
          Map.entry("48", "DNSKEY"),
          Map.entry("64", "SVCB"),
          Map.entry("65", "HTTPS"),
          Map.entry("255", "ANY"),
          Map.entry("257", "CAA"));

  /** DNS RCODE numeric → name. */
  private static final Map<String, String> RCODE_NAMES =
      Map.ofEntries(
          Map.entry("0", "NOERROR"),
          Map.entry("1", "FORMERR"),
          Map.entry("2", "SERVFAIL"),
          Map.entry("3", "NXDOMAIN"),
          Map.entry("4", "NOTIMP"),
          Map.entry("5", "REFUSED"),
          Map.entry("9", "NOTAUTH"));

  private final DnsQueryLogRepository dnsQueryLogRepository;

  @Value("${tracepcap.dns.nxdomain-suspicious-ratio:0.5}")
  private double nxdomainSuspiciousRatio;

  @Value("${tracepcap.dns.nxdomain-min-queries:20}")
  private int nxdomainMinQueries;

  public DnsQueryLogExtractor(DnsQueryLogRepository dnsQueryLogRepository) {
    this.dnsQueryLogRepository = dnsQueryLogRepository;
  }

  @Override
  public String role() {
    return ROLE;
  }

  /** Mutable accumulator for one (serverIp, queryName, queryType) group. */
  static final class QueryAgg {
    int count;
    final Set<String> resolvedIps = new LinkedHashSet<>();
    String responseCode; // representative rcode name
    boolean resolvable; // true once any response was NOERROR with at least one answer
  }

  /** Per-server NXDOMAIN bookkeeping for suspicion scoring. */
  static final class ServerStats {
    int totalResponses;
    int nxdomainResponses;
  }

  @Override
  public HostServiceLogResult extractAndPersist(FileEntity file, File pcap) {
    Map<String, QueryAgg> groups = new LinkedHashMap<>(); // key: serverIp|queryName|queryType
    Map<String, ServerStats> serverStats = new LinkedHashMap<>();

    runTshark(pcap, groups, serverStats);

    // Persist aggregated rows.
    List<DnsQueryLogEntity> rows = new ArrayList<>(groups.size());
    for (Map.Entry<String, QueryAgg> e : groups.entrySet()) {
      String[] key = e.getKey().split("\\|", -1);
      QueryAgg agg = e.getValue();
      rows.add(
          DnsQueryLogEntity.builder()
              .file(file)
              .serverIp(key[0])
              .queryName(key[1])
              .queryType(key[2].isEmpty() ? null : key[2])
              .responseCode(agg.responseCode)
              .resolvedIps(agg.resolvedIps.isEmpty() ? null : String.join(",", agg.resolvedIps))
              .queryCount(agg.count)
              .resolvable(agg.resolvable)
              .build());
    }
    if (!rows.isEmpty()) {
      try {
        dnsQueryLogRepository.saveAll(rows);
      } catch (Exception ex) {
        log.warn("Failed to persist {} DNS query log row(s): {}", rows.size(), ex.getMessage());
      }
    }

    // Score servers for suspicion.
    List<HostServiceSuspicion> suspicions = new ArrayList<>();
    for (Map.Entry<String, ServerStats> e : serverStats.entrySet()) {
      ServerStats s = e.getValue();
      if (s.totalResponses < nxdomainMinQueries) continue;
      double ratio = (double) s.nxdomainResponses / s.totalResponses;
      if (ratio >= nxdomainSuspiciousRatio) {
        String reason =
            String.format(
                "%.0f%% NXDOMAIN over %d responses", ratio * 100, s.totalResponses);
        suspicions.add(new HostServiceSuspicion(e.getKey(), ROLE, reason));
      }
    }

    log.info(
        "DNS query log: {} aggregated row(s) across {} server(s), {} flagged suspicious",
        rows.size(),
        serverStats.size(),
        suspicions.size());
    // Every host that answered a DNS query is a DNS server, regardless of suspicion.
    return new HostServiceLogResult(new LinkedHashSet<>(serverStats.keySet()), suspicions);
  }

  // ── tshark pass ───────────────────────────────────────────────────────────

  private void runTshark(
      File pcap, Map<String, QueryAgg> groups, Map<String, ServerStats> serverStats) {
    // Fields (pipe-separated): 0 ip.src  1 dns.qry.name  2 dns.qry.type
    //   3 dns.flags.rcode  4 dns.a  5 dns.aaaa  6 dns.count.answers
    // Default occurrence aggregator (",") keeps every answer record in dns.a/dns.aaaa.
    // dns.count.answers (ANCOUNT) lets us treat any successfully-answered query as resolved —
    // including non-address types (MX, TXT, CNAME, PTR, SRV …) that carry no A/AAAA record.
    ProcessBuilder pb =
        new ProcessBuilder(
            "tshark",
            "-r",
            pcap.getAbsolutePath(),
            "-Y",
            "dns.flags.response==1",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-e",
            "ip.src",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.qry.type",
            "-e",
            "dns.flags.rcode",
            "-e",
            "dns.a",
            "-e",
            "dns.aaaa",
            "-e",
            "dns.count.answers");
    pb.redirectErrorStream(false);

    Process process = null;
    ExecutorService ioExecutor = null;
    try {
      process = pb.start();
      final Process proc = process;

      Thread stderrThread =
          new Thread(
              () -> {
                try (BufferedReader err =
                    new BufferedReader(
                        new InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8))) {
                  while (err.readLine() != null) {
                    // discard
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });
      stderrThread.setDaemon(true);
      stderrThread.start();

      ioExecutor = Executors.newSingleThreadExecutor();
      Future<?> stdoutTask =
          ioExecutor.submit(
              () -> {
                try (BufferedReader reader =
                    new BufferedReader(
                        new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                  String line;
                  while ((line = reader.readLine()) != null) {
                    if (!line.isEmpty()) parseRow(line.split("\\|", -1), groups, serverStats);
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });

      boolean finished = process.waitFor(2, TimeUnit.MINUTES);
      if (!finished) {
        log.warn("DNS query log extraction timed out; using partial results");
      } else {
        int exit = process.exitValue();
        if (exit != 0) {
          log.warn("DNS query log: tshark exited with code {}; results may be partial", exit);
        }
        try {
          stdoutTask.get(5, TimeUnit.SECONDS);
        } catch (Exception ignored) {
          // best-effort
        }
      }
    } catch (InterruptedException e) {
      log.warn("DNS query log extraction interrupted");
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      log.warn("DNS query log extraction failed: {}", e.getMessage());
    } finally {
      if (process != null) process.destroyForcibly();
      if (ioExecutor != null) ioExecutor.shutdownNow();
    }
  }

  // ── Row parsing ─────────────────────────────────────────────────────────────

  static void parseRow(
      String[] f, Map<String, QueryAgg> groups, Map<String, ServerStats> serverStats) {
    if (f.length < 7) return;
    String serverIp = trimToNull(f[0]);
    String queryName = stripTrailingDot(firstValue(f[1]));
    if (serverIp == null || queryName == null) return;
    if (queryName.length() > QUERY_NAME_MAX_LENGTH) {
      queryName = queryName.substring(0, QUERY_NAME_MAX_LENGTH);
    }

    String queryType = qtypeName(firstValue(f[2]));
    String rawRcode = firstValue(f[3]);
    String responseCode = rcodeName(rawRcode);
    boolean isNoError = "0".equals(rawRcode);
    boolean isNxdomain = "3".equals(rawRcode);

    Set<String> answers = new LinkedHashSet<>();
    addValues(answers, f[4]);
    addValues(answers, f[5]);
    // A query is "resolved" when it was answered successfully (NOERROR with at least one answer
    // record), regardless of record type — an MX/TXT/CNAME/PTR lookup with no A/AAAA still counts.
    // NOERROR with zero answers (NODATA) and NXDOMAIN are both unresolved.
    boolean resolvable = isNoError && parseAnswerCount(f[6]) > 0;

    // Per-server NXDOMAIN scoring (packet-level).
    ServerStats stats = serverStats.computeIfAbsent(serverIp, k -> new ServerStats());
    stats.totalResponses++;
    if (isNxdomain) stats.nxdomainResponses++;

    // Aggregate into the (server, name, type) group.
    String key = serverIp + "|" + queryName + "|" + (queryType == null ? "" : queryType);
    QueryAgg agg = groups.computeIfAbsent(key, k -> new QueryAgg());
    agg.count++;
    agg.resolvedIps.addAll(answers);
    if (resolvable) {
      agg.resolvable = true;
      agg.responseCode = responseCode; // a successful answer wins the representative code
    } else if (agg.responseCode == null) {
      agg.responseCode = responseCode;
    }
  }

  // ── Field helpers ────────────────────────────────────────────────────────────

  /** Splits a comma-aggregated tshark field into non-blank values, appending to {@code into}. */
  private static void addValues(Set<String> into, String field) {
    if (field == null) return;
    for (String part : field.split(",")) {
      String v = part.trim();
      if (!v.isEmpty()) into.add(v);
    }
  }

  /** tshark may join multiple occurrences with ','; take the first non-blank token. */
  private static String firstValue(String field) {
    if (field == null) return null;
    String trimmed = field.trim();
    if (trimmed.isEmpty()) return null;
    int comma = trimmed.indexOf(',');
    return comma >= 0 ? trimmed.substring(0, comma).trim() : trimmed;
  }

  private static String trimToNull(String raw) {
    if (raw == null) return null;
    String t = raw.trim();
    return t.isEmpty() ? null : t;
  }

  /** Parses tshark's dns.count.answers (ANCOUNT); returns 0 when absent or unparseable. */
  private static int parseAnswerCount(String raw) {
    String v = firstValue(raw);
    if (v == null) return 0;
    try {
      return Integer.parseInt(v);
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  private static String stripTrailingDot(String raw) {
    if (raw == null) return null;
    String h = raw.trim();
    if (h.isEmpty()) return null;
    return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
  }

  private static String qtypeName(String numeric) {
    if (numeric == null) return null;
    return QTYPE_NAMES.getOrDefault(numeric, "TYPE" + numeric);
  }

  private static String rcodeName(String numeric) {
    if (numeric == null) return null;
    return RCODE_NAMES.getOrDefault(numeric, "RCODE" + numeric);
  }
}
