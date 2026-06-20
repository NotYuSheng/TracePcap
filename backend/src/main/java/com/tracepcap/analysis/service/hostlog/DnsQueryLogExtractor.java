package com.tracepcap.analysis.service.hostlog;

import com.tracepcap.analysis.entity.DnsQueryLogEntity;
import com.tracepcap.analysis.repository.DnsQueryLogRepository;
import com.tracepcap.file.entity.FileEntity;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
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

  /** Aggregation key — typed rather than a delimiter-joined string so a pipe in a query name (as
   *  tunnelled/malformed traffic may contain) can't collide or corrupt keys. */
  record QueryKey(String serverIp, String queryName, String queryType) {}

  /** Mutable accumulator for one (serverIp, queryName, queryType) group. */
  static final class QueryAgg {
    int count;
    final Set<String> resolvedIps = new LinkedHashSet<>();
    String responseCode; // representative rcode name
    boolean resolvable; // true once any response was NOERROR with at least one answer
    Long sampleFrame; // frame.number of the first response packet (for "view packet" links)
  }

  /** Per-server NXDOMAIN bookkeeping for suspicion scoring. */
  static final class ServerStats {
    int totalResponses;
    int nxdomainResponses;
  }

  @Override
  public HostServiceLogResult extractAndPersist(FileEntity file, File pcap) {
    Map<QueryKey, QueryAgg> groups = new LinkedHashMap<>();
    Map<String, ServerStats> serverStats = new LinkedHashMap<>();

    runTshark(pcap, groups, serverStats);

    // Persist aggregated rows.
    List<DnsQueryLogEntity> rows = new ArrayList<>(groups.size());
    for (Map.Entry<QueryKey, QueryAgg> e : groups.entrySet()) {
      QueryKey key = e.getKey();
      QueryAgg agg = e.getValue();
      rows.add(
          DnsQueryLogEntity.builder()
              .file(file)
              .serverIp(key.serverIp())
              .queryName(key.queryName())
              .queryType(key.queryType().isEmpty() ? null : key.queryType())
              .responseCode(agg.responseCode)
              .resolvedIps(agg.resolvedIps.isEmpty() ? null : String.join(",", agg.resolvedIps))
              .queryCount(agg.count)
              .resolvable(agg.resolvable)
              .sampleFrame(agg.sampleFrame)
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
      if (ratio > nxdomainSuspiciousRatio) { // strictly "exceeds" the configured threshold
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
    Map<String, String> roleByServerIp = new LinkedHashMap<>();
    for (String ip : serverStats.keySet()) roleByServerIp.put(ip, ROLE);
    return new HostServiceLogResult(roleByServerIp, suspicions);
  }

  // ── tshark pass ───────────────────────────────────────────────────────────

  private void runTshark(
      File pcap, Map<QueryKey, QueryAgg> groups, Map<String, ServerStats> serverStats) {
    // Fields (pipe-separated): 0 frame.number  1 ip.src  2 dns.qry.name  3 dns.qry.type
    //   4 dns.flags.rcode  5 dns.a  6 dns.aaaa  7 dns.count.answers
    // frame.number leads (numeric, no '|') and the five answer-related fields trail, so a '|' in the
    // query name still parses via right-anchoring. dns.count.answers (ANCOUNT) lets us treat any
    // successfully-answered query as resolved — including non-address types (MX/TXT/CNAME/PTR/SRV).
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
            "frame.number",
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
    // Discard stderr natively (no drain thread needed); we only consume stdout.
    pb.redirectError(ProcessBuilder.Redirect.DISCARD);

    Process process = null;
    ExecutorService ioExecutor = null;
    try {
      process = pb.start();
      final Process proc = process;

      ioExecutor = Executors.newSingleThreadExecutor();
      Future<?> stdoutTask =
          ioExecutor.submit(
              () -> {
                try (BufferedReader reader =
                    new BufferedReader(
                        new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                  String line;
                  while ((line = reader.readLine()) != null) {
                    if (!line.isEmpty()) parseRow(line, groups, serverStats);
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
          // tshark has exited; give the reader a generous window to drain any buffered output so a
          // large query log isn't silently truncated. Match the overall extraction budget.
          stdoutTask.get(2, TimeUnit.MINUTES);
        } catch (Exception e) {
          log.warn("DNS query log: stdout drain did not complete; results may be partial");
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
      String line, Map<QueryKey, QueryAgg> groups, Map<String, ServerStats> serverStats) {
    String[] f = line.split("\\|", -1);
    if (f.length < 8) return;
    // Fields are fixed except the query name (field 2), which — in tunnelled/malformed DNS — may
    // itself contain the '|' separator. frame.number + ip.src lead and the five answer fields trail,
    // so re-join everything in between to recover the full query name.
    Long frame = parseFrame(f[0]);
    String serverIp = trimToNull(f[1]);
    String rawQueryName =
        (f.length == 8) ? f[2] : String.join("|", Arrays.copyOfRange(f, 2, f.length - 5));
    String queryName = stripTrailingDot(firstValue(rawQueryName));
    if (serverIp == null || queryName == null) return;
    if (queryName.length() > QUERY_NAME_MAX_LENGTH) {
      queryName = queryName.substring(0, QUERY_NAME_MAX_LENGTH);
    }

    String queryType = qtypeName(firstValue(f[f.length - 5]));
    String rawRcode = firstValue(f[f.length - 4]);
    String responseCode = rcodeName(rawRcode);
    boolean isNoError = "0".equals(rawRcode);
    boolean isNxdomain = "3".equals(rawRcode);

    Set<String> answers = new LinkedHashSet<>();
    addValues(answers, f[f.length - 3]);
    addValues(answers, f[f.length - 2]);
    // A query is "resolved" when it was answered successfully (NOERROR with at least one answer
    // record), regardless of record type — an MX/TXT/CNAME/PTR lookup with no A/AAAA still counts.
    // NOERROR with zero answers (NODATA) and NXDOMAIN are both unresolved.
    boolean resolvable = isNoError && parseAnswerCount(f[f.length - 1]) > 0;

    // Per-server NXDOMAIN scoring (packet-level).
    ServerStats stats = serverStats.computeIfAbsent(serverIp, k -> new ServerStats());
    stats.totalResponses++;
    if (isNxdomain) stats.nxdomainResponses++;

    // Aggregate into the (server, name, type) group.
    QueryKey key = new QueryKey(serverIp, queryName, queryType == null ? "" : queryType);
    QueryAgg agg = groups.computeIfAbsent(key, k -> new QueryAgg());
    agg.count++;
    agg.resolvedIps.addAll(answers);
    if (agg.sampleFrame == null && frame != null) agg.sampleFrame = frame; // first response packet
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

  /** Parses a tshark frame.number; returns null when absent or unparseable. */
  private static Long parseFrame(String raw) {
    String v = firstValue(raw);
    if (v == null) return null;
    try {
      return Long.parseLong(v);
    } catch (NumberFormatException e) {
      return null;
    }
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
