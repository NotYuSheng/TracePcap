package com.tracepcap.analysis.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Enriches external (non-RFC1918) IP addresses with country and ASN information using the
 * ip-api.com batch endpoint. Results are cached in the {@code ip_geo_cache} table so repeated
 * analyses never re-fetch an already-known IP.
 *
 * <p>Geo enrichment is best-effort: if the API is unreachable (offline deployment) the service logs
 * a warning and returns whatever is already in the cache.
 *
 * <p>Note: ip-api.com requires a Pro plan for HTTPS; the free tier only supports HTTP. IP addresses
 * sent to the API are therefore unencrypted in transit. In air-gapped or high-security environments
 * set {@code GEO_ENRICHMENT_ENABLED=false} to disable all external lookups.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GeoIpService {

  // ip-api.com free tier only supports HTTP — see class-level javadoc.
  private static final String API_URL =
      "http://ip-api.com/batch?fields=status,countryCode,country,as,org,query";
  private static final int BATCH_SIZE = 100;

  @Value("${tracepcap.geo.enabled:true}")
  private boolean geoEnabled;

  @Value("${tracepcap.geo.timeout-seconds:10}")
  private int timeoutSeconds;

  private final IpGeoInfoRepository geoInfoRepository;

  /** Shared RestClient — initialised once in {@link #init()} and reused for all requests. */
  private RestClient restClient;

  /**
   * Tracks whether a warning has already been logged for the current analysis run so we don't flood
   * the log if the API is unreachable across multiple batches.
   */
  private final AtomicBoolean warnedThisRun = new AtomicBoolean(false);

  @PostConstruct
  void init() {
    SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout((int) Duration.ofSeconds(timeoutSeconds).toMillis());
    factory.setReadTimeout((int) Duration.ofSeconds(timeoutSeconds).toMillis());
    restClient =
        RestClient.builder()
            .baseUrl(API_URL)
            .defaultHeader("Content-Type", "application/json")
            .requestFactory(factory)
            .build();
  }

  public record GeoResult(String country, String countryCode, String asn, String org) {}

  /**
   * Given a set of IP strings, returns a map of IP → GeoResult for all external IPs. Private,
   * loopback, and link-local addresses are silently skipped.
   */
  public Map<String, GeoResult> lookupExternal(Set<String> ips) {
    if (!geoEnabled || ips == null || ips.isEmpty()) return Map.of();

    List<String> external = ips.stream().filter(ip -> !isPrivate(ip)).collect(Collectors.toList());
    if (external.isEmpty()) return Map.of();

    // Reset per-run warning flag so each new analysis run gets at most one warning
    warnedThisRun.set(false);

    // Load cached entries
    Map<String, GeoResult> result = new HashMap<>();
    List<IpGeoInfoEntity> cached = geoInfoRepository.findAllByIpIn(external);
    Set<String> cachedIps = new HashSet<>();
    for (IpGeoInfoEntity e : cached) {
      result.put(
          e.getIp(), new GeoResult(e.getCountry(), e.getCountryCode(), e.getAsn(), e.getOrg()));
      cachedIps.add(e.getIp());
    }

    // Fetch cache misses
    List<String> misses =
        external.stream().filter(ip -> !cachedIps.contains(ip)).collect(Collectors.toList());
    if (!misses.isEmpty()) {
      Map<String, GeoResult> fetched = fetchFromApi(misses);
      result.putAll(fetched);

      // Persist new results
      List<IpGeoInfoEntity> toSave =
          fetched.entrySet().stream()
              .map(
                  e ->
                      IpGeoInfoEntity.builder()
                          .ip(e.getKey())
                          .country(e.getValue().country())
                          .countryCode(e.getValue().countryCode())
                          .asn(e.getValue().asn())
                          .org(e.getValue().org())
                          .build())
              .collect(Collectors.toList());
      if (!toSave.isEmpty()) {
        geoInfoRepository.saveAll(toSave);
      }
    }

    return result;
  }

  /** Returns true if the IP is RFC1918, loopback, link-local, or IPv6 ULA/loopback. */
  static boolean isPrivate(String ip) {
    if (ip == null || ip.isBlank()) return true;
    String trimmed = ip.trim();
    // IPv6 loopback and ULA
    if (trimmed.equals("::1")
        || trimmed.startsWith("fc")
        || trimmed.startsWith("fd")
        || trimmed.startsWith("fe80")) {
      return true;
    }
    // IPv4 private ranges
    if (trimmed.startsWith("10.")) return true;
    if (trimmed.startsWith("127.")) return true;
    if (trimmed.startsWith("169.254.")) return true;
    if (trimmed.startsWith("192.168.")) return true;
    if (trimmed.startsWith("172.")) {
      // 172.16.0.0 – 172.31.255.255
      String[] parts = trimmed.split("\\.");
      if (parts.length >= 2) {
        try {
          int second = Integer.parseInt(parts[1]);
          if (second >= 16 && second <= 31) return true;
        } catch (NumberFormatException ignored) {
          // fall through
        }
      }
    }
    return false;
  }

  private Map<String, GeoResult> fetchFromApi(List<String> ips) {
    Map<String, GeoResult> result = new HashMap<>();

    // Process in batches of BATCH_SIZE
    for (int i = 0; i < ips.size(); i += BATCH_SIZE) {
      List<String> batch = ips.subList(i, Math.min(i + BATCH_SIZE, ips.size()));
      List<Map<String, String>> requestBody =
          batch.stream().map(ip -> Map.of("query", ip)).collect(Collectors.toList());
      try {
        IpApiResponse[] responses =
            restClient.post().body(requestBody).retrieve().body(IpApiResponse[].class);

        if (responses != null) {
          for (IpApiResponse resp : responses) {
            if (resp.getQuery() == null) continue;
            if ("success".equals(resp.getStatus())) {
              // ip-api.com returns ASN in the "as" field as e.g. "AS15169 Google LLC"
              // and org separately
              String asn = extractAsn(resp.getAs());
              result.put(
                  resp.getQuery(),
                  new GeoResult(resp.getCountry(), resp.getCountryCode(), asn, resp.getOrg()));
            } else {
              // Still cache the miss so we don't keep hitting the API for unresolvable IPs
              result.put(resp.getQuery(), new GeoResult(null, null, null, null));
            }
          }
        }
      } catch (Exception e) {
        // Log only once per analysis run to avoid flooding the log when the API is unreachable
        if (warnedThisRun.compareAndSet(false, true)) {
          log.warn(
              "GeoIP lookup failed (further failures this run will be suppressed): {}",
              e.getMessage());
        }
        // Return partial results — don't fail the caller
      }
    }
    return result;
  }

  /** Extracts just the ASN number from a string like "AS15169 Google LLC". */
  private static String extractAsn(String asField) {
    if (asField == null || asField.isBlank()) return null;
    int space = asField.indexOf(' ');
    return space > 0 ? asField.substring(0, space) : asField;
  }

  @Data
  @JsonIgnoreProperties(ignoreUnknown = true)
  static class IpApiResponse {
    private String status;
    private String country;

    @JsonProperty("countryCode")
    private String countryCode;

    @JsonProperty("as")
    private String as;

    private String org;
    private String query;
  }
}
