package com.tracepcap.analysis.service.hostlog;

import com.tracepcap.analysis.entity.HttpEndpointLogEntity;
import com.tracepcap.analysis.repository.HttpEndpointLogRepository;
import com.tracepcap.file.entity.FileEntity;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Detects web/API-server hosts and logs the cleartext HTTP endpoints they served (#362 follow-up) —
 * the web/API counterpart of {@link DnsQueryLogExtractor}.
 *
 * <p>Two read-only tshark passes:
 *
 * <ul>
 *   <li><b>HTTP</b> ({@code http.response}): aggregates per {@code (serverIp, method, path)} into
 *       {@link HttpEndpointLogEntity} rows — request count, status-class counts (2xx/3xx vs 4xx vs
 *       5xx), representative content type and {@code Server} header software.
 *   <li><b>TLS</b> ({@code tls.handshake.type==2}, ServerHello): records hosts that served TLS, so
 *       HTTPS-only servers are still classified as web servers (their endpoints are encrypted, but
 *       their TLS metadata is surfaced at read time from the existing conversation TLS fields).
 * </ul>
 *
 * <p>Each server is tagged {@code "api"} when its responses look API-like (JSON content type, REST
 * write verbs, or {@code /api}-style paths) or {@code "web"} otherwise; TLS-only servers default to
 * {@code "web"}. Degrades gracefully and never throws.
 *
 * <p>Note: HTTP endpoint/Server-header data is only visible for <b>cleartext HTTP/1.x</b> — HTTPS
 * request contents are encrypted.
 */
@Slf4j
@Service
public class WebServerLogExtractor implements HostServiceLogExtractor {

  public static final String ROLE_WEB = "web";
  public static final String ROLE_API = "api";

  private static final int PATH_MAX_LENGTH = 2048;

  private final HttpEndpointLogRepository httpEndpointLogRepository;

  public WebServerLogExtractor(HttpEndpointLogRepository httpEndpointLogRepository) {
    this.httpEndpointLogRepository = httpEndpointLogRepository;
  }

  @Override
  public String role() {
    return ROLE_WEB;
  }

  /** Mutable accumulator for one (serverIp, method, path) endpoint. */
  static final class EndpointAgg {
    int requestCount;
    int successCount;
    int clientErrorCount;
    int serverErrorCount;
    final Map<Integer, Integer> statusCounts = new LinkedHashMap<>();
    String contentType; // representative (first seen)
    String serverSoftware; // first Server header seen for this endpoint's server
    Long requestFrame; // frame.number of the first request (for "view packet" links)
    Long responseFrame; // frame.number of the first response
  }

  /** Per-server bookkeeping for the api/web decision and the read-side enumeration check. */
  static final class WebServerStats {
    int totalResponses;
    int jsonResponses;
    int htmlResponses;
    boolean hasApiPath;
    boolean hasWriteVerb;
  }

  @Override
  public HostServiceLogResult extractAndPersist(FileEntity file, File pcap) {
    Map<String, EndpointAgg> endpoints = new LinkedHashMap<>(); // key: serverIp|method|path
    Map<String, WebServerStats> serverStats = new LinkedHashMap<>();
    Set<String> tlsServers = new LinkedHashSet<>();

    // HTTP pass — requests carry the method, responses carry the status/content-type/Server header;
    // tshark surfaces the request URI on the response but not the method, so we correlate request →
    // response per TCP stream (FIFO, valid for HTTP/1.x ordering).
    // Fields: 0 tcp.stream 1 ip.src 2 ip.dst 3 method 4 uri 5 status 6 content_type 7 server
    //   8 frame.number
    Map<String, Deque<String[]>> pendingByStream = new HashMap<>();
    runPass(
        pcap,
        "http",
        new String[] {
          "tcp.stream", "ip.src", "ip.dst", "http.request.method", "http.request.uri",
          "http.response.code", "http.content_type", "http.server", "frame.number"
        },
        f -> parseHttpFrame(f, endpoints, serverStats, pendingByStream));

    // TLS pass — ServerHello source IP is the TLS server.
    runPass(
        pcap,
        "tls.handshake.type==2",
        new String[] {"ip.src"},
        f -> {
          String ip = trimToNull(f[0]);
          if (ip != null) tlsServers.add(ip);
        });

    persist(file, endpoints);

    // Assign each server a role: api-like HTTP servers → "api", other HTTP servers and TLS-only
    // servers → "web".
    Map<String, String> roleByServerIp = new LinkedHashMap<>();
    for (Map.Entry<String, WebServerStats> e : serverStats.entrySet()) {
      roleByServerIp.put(e.getKey(), isApiLike(e.getValue()) ? ROLE_API : ROLE_WEB);
    }
    for (String ip : tlsServers) roleByServerIp.putIfAbsent(ip, ROLE_WEB);

    log.info(
        "HTTP endpoint log: {} endpoint row(s) across {} HTTP server(s); {} TLS server(s)",
        endpoints.size(),
        serverStats.size(),
        tlsServers.size());
    // Web suspicion (4xx enumeration) is computed at read time from the persisted rows.
    return new HostServiceLogResult(roleByServerIp, List.of());
  }

  private void persist(FileEntity file, Map<String, EndpointAgg> endpoints) {
    List<HttpEndpointLogEntity> rows = new ArrayList<>(endpoints.size());
    for (Map.Entry<String, EndpointAgg> e : endpoints.entrySet()) {
      String[] key = e.getKey().split("\\|", 3);
      EndpointAgg agg = e.getValue();
      rows.add(
          HttpEndpointLogEntity.builder()
              .file(file)
              .serverIp(key[0])
              .method(key[1].isEmpty() ? null : key[1])
              .path(key[2])
              .requestCount(agg.requestCount)
              .successCount(agg.successCount)
              .clientErrorCount(agg.clientErrorCount)
              .serverErrorCount(agg.serverErrorCount)
              .topStatus(topStatus(agg.statusCounts))
              .contentType(agg.contentType)
              .serverSoftware(agg.serverSoftware)
              .requestFrame(agg.requestFrame)
              .responseFrame(agg.responseFrame)
              .build());
    }
    if (!rows.isEmpty()) {
      try {
        httpEndpointLogRepository.saveAll(rows);
      } catch (Exception ex) {
        log.warn("Failed to persist {} HTTP endpoint row(s): {}", rows.size(), ex.getMessage());
      }
    }
  }

  // ── Row parsing ─────────────────────────────────────────────────────────────

  /**
   * Processes one HTTP frame (request or response). Requests are queued per stream so the matching
   * response can recover the method+path; responses are bucketed by status class into endpoint rows.
   */
  static void parseHttpFrame(
      String[] f,
      Map<String, EndpointAgg> endpoints,
      Map<String, WebServerStats> serverStats,
      Map<String, Deque<String[]>> pendingByStream) {
    if (f.length < 8) return;
    String stream = f[0];
    String method = upperOrNull(firstValue(f[3]));
    String uri = trimToNull(f[4]); // not firstValue — a request URI may legitimately contain ','
    Integer status = parseIntOrNull(firstValue(f[5]));

    if (method != null && uri != null) {
      // Request frame — the server is the destination.
      String server = trimToNull(f[2]);
      if (server == null) return;
      String path = normalisePath(uri);
      WebServerStats stats = serverStats.computeIfAbsent(server, k -> new WebServerStats());
      if (path != null && isApiPath(path)) stats.hasApiPath = true;
      if (isWriteVerb(method)) stats.hasWriteVerb = true;
      if (path != null) {
        String reqFrame = f.length > 8 ? trimToNull(f[8]) : null;
        pendingByStream
            .computeIfAbsent(stream, k -> new ArrayDeque<>())
            .addLast(new String[] {method, path, reqFrame});
      }
    } else if (status != null) {
      // Response frame — the server is the source.
      String server = trimToNull(f[1]);
      if (server == null) return;
      String contentType = normaliseContentType(firstValue(f[6]));
      String serverSoftware = trimToNull(f[7]);
      Long respFrame = parseLongOrNull(f.length > 8 ? firstValue(f[8]) : null);
      WebServerStats stats = serverStats.computeIfAbsent(server, k -> new WebServerStats());
      stats.totalResponses++;
      if (contentType != null && contentType.contains("json")) stats.jsonResponses++;
      else if (contentType != null && contentType.contains("html")) stats.htmlResponses++;

      // Recover the request's method+path+frame (FIFO within the stream); fall back to the response's
      // own request URI when unmatched.
      Deque<String[]> queue = pendingByStream.get(stream);
      String[] req = null;
      if (queue != null) {
        req = queue.pollFirst();
        if (queue.isEmpty()) pendingByStream.remove(stream); // free finished streams
      }
      String reqMethod = req != null ? req[0] : null;
      String path = req != null ? req[1] : normalisePath(uri);
      Long reqFrame = (req != null) ? parseLongOrNull(req[2]) : null;
      if (path == null) return;
      recordEndpoint(
          server, reqMethod, path, status, contentType, serverSoftware, reqFrame, respFrame, endpoints);
    }
  }

  /** Aggregates one matched request/response into its {@code (server, method, path)} endpoint row. */
  static void recordEndpoint(
      String server,
      String method,
      String path,
      int status,
      String contentType,
      String serverSoftware,
      Long requestFrame,
      Long responseFrame,
      Map<String, EndpointAgg> endpoints) {
    String key = server + "|" + (method == null ? "" : method) + "|" + path;
    EndpointAgg agg = endpoints.computeIfAbsent(key, k -> new EndpointAgg());
    agg.requestCount++;
    agg.statusCounts.merge(status, 1, Integer::sum);
    if (status >= 500) agg.serverErrorCount++;
    else if (status >= 400) agg.clientErrorCount++;
    else agg.successCount++;
    if (agg.contentType == null && contentType != null) agg.contentType = contentType;
    if (agg.serverSoftware == null && serverSoftware != null) agg.serverSoftware = serverSoftware;
    if (agg.requestFrame == null && requestFrame != null) agg.requestFrame = requestFrame;
    if (agg.responseFrame == null && responseFrame != null) agg.responseFrame = responseFrame;
  }

  /** A server is "API-like" when JSON dominates its responses, or it uses REST write verbs / api paths. */
  static boolean isApiLike(WebServerStats s) {
    boolean jsonDominant = s.jsonResponses > 0 && s.jsonResponses >= s.htmlResponses;
    return jsonDominant || s.hasApiPath || s.hasWriteVerb;
  }

  // ── tshark pass plumbing ─────────────────────────────────────────────────────

  /** Runs one read-only tshark pass and feeds each non-empty output row (split on '|') to {@code rowConsumer}. */
  private void runPass(
      File pcap, String displayFilter, String[] fields, Consumer<String[]> rowConsumer) {
    List<String> cmd = new ArrayList<>();
    cmd.add("tshark");
    cmd.add("-r");
    cmd.add(pcap.getAbsolutePath());
    cmd.add("-Y");
    cmd.add(displayFilter);
    cmd.add("-T");
    cmd.add("fields");
    cmd.add("-E");
    cmd.add("separator=|");
    for (String field : fields) {
      cmd.add("-e");
      cmd.add(field);
    }
    ProcessBuilder pb = new ProcessBuilder(cmd);
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
                    if (!line.isEmpty()) rowConsumer.accept(line.split("\\|", -1));
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });

      boolean finished = process.waitFor(2, TimeUnit.MINUTES);
      if (!finished) {
        log.warn("Web server extraction ({}) timed out; using partial results", displayFilter);
      } else {
        int exit = process.exitValue();
        if (exit != 0) {
          log.warn("Web server extraction: tshark exited with code {} for filter {}", exit, displayFilter);
        }
        try {
          stdoutTask.get(2, TimeUnit.MINUTES);
        } catch (Exception e) {
          log.warn("Web server extraction: stdout drain incomplete; results may be partial");
        }
      }
    } catch (InterruptedException e) {
      log.warn("Web server extraction interrupted");
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      log.warn("Web server extraction failed: {}", e.getMessage());
    } finally {
      if (process != null) process.destroyForcibly();
      if (ioExecutor != null) ioExecutor.shutdownNow();
    }
  }

  // ── Field helpers ────────────────────────────────────────────────────────────

  private static boolean isApiPath(String path) {
    String p = path.toLowerCase();
    return p.startsWith("/api/")
        || p.equals("/api")
        || p.startsWith("/v1/")
        || p.startsWith("/v2/")
        || p.contains("/graphql")
        || p.startsWith("/rest/");
  }

  private static boolean isWriteVerb(String method) {
    return method.equals("PUT") || method.equals("DELETE") || method.equals("PATCH");
  }

  /** tshark may join multiple occurrences with ','; take the first non-blank token. */
  private static String firstValue(String field) {
    if (field == null) return null;
    String t = field.trim();
    if (t.isEmpty()) return null;
    int comma = t.indexOf(',');
    return comma >= 0 ? t.substring(0, comma).trim() : t;
  }

  private static String trimToNull(String raw) {
    if (raw == null) return null;
    String t = raw.trim();
    return t.isEmpty() ? null : t;
  }

  private static String upperOrNull(String raw) {
    return raw == null ? null : raw.toUpperCase();
  }

  /** Strips the query string and caps length, so endpoints aggregate by path. */
  private static String normalisePath(String raw) {
    String p = trimToNull(raw);
    if (p == null) return null;
    int q = p.indexOf('?');
    if (q >= 0) p = p.substring(0, q);
    if (p.isEmpty()) p = "/";
    if (p.length() > PATH_MAX_LENGTH) p = p.substring(0, PATH_MAX_LENGTH);
    return p;
  }

  /** Lower-cases and drops any "; charset=…" parameter. */
  private static String normaliseContentType(String raw) {
    String c = trimToNull(raw);
    if (c == null) return null;
    int semi = c.indexOf(';');
    if (semi >= 0) c = c.substring(0, semi).trim();
    return c.toLowerCase();
  }

  private static Integer parseIntOrNull(String raw) {
    if (raw == null) return null;
    try {
      return Integer.parseInt(raw.trim());
    } catch (NumberFormatException e) {
      return null;
    }
  }

  /** Parses a tshark frame.number; returns null when absent or unparseable. */
  private static Long parseLongOrNull(String raw) {
    if (raw == null) return null;
    try {
      return Long.parseLong(raw.trim());
    } catch (NumberFormatException e) {
      return null;
    }
  }

  static Integer topStatus(Map<Integer, Integer> statusCounts) {
    return statusCounts.entrySet().stream()
        .max(Map.Entry.comparingByValue())
        .map(Map.Entry::getKey)
        .orElse(null);
  }
}
