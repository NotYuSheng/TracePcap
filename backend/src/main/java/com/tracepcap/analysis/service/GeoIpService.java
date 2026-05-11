package com.tracepcap.analysis.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.maxmind.db.CHMCache;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Enriches external (non-RFC1918) IP addresses with geo and ASN information.
 *
 * <p>Lookup strategy (per cache miss):
 * <ol>
 *   <li>If internet is reachable: query <b>ipinfo.io</b> (free, no key, includes ASN/org).
 *   <li>Otherwise: query the bundled <b>DB-IP Lite MMDB</b> (offline fallback).
 * </ol>
 *
 * <p>The source of each result ("ipinfo" or "mmdb") is stored in {@code ip_geo_cache.geo_source}
 * so the frontend can communicate accuracy context to the user.
 *
 * <p>Results are cached permanently; stale entries (older than {@code CACHE_TTL_DAYS}) are
 * re-looked up when the MMDB is available.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GeoIpService {

  @Value("${tracepcap.geo.enabled:true}")
  private boolean geoEnabled;

  @Value("${tracepcap.geo.mmdb-path:}")
  private String mmdbPathOverride;

  private final IpGeoInfoRepository geoInfoRepository;
  private final ObjectMapper objectMapper;

  private DatabaseReader dbReader;

  /** How long before a cached entry is considered stale and re-looked up. */
  private static final int CACHE_TTL_DAYS = 30;

  /** ipinfo.io base URL — free tier, no key required for basic fields. */
  private static final String IPINFO_URL = "https://ipinfo.io/%s/json";

  /** Connectivity probe URL — lightweight HEAD request to check internet access. */
  private static final String PROBE_URL = "https://ipinfo.io";

  private static final int CONNECT_TIMEOUT_MS = 3_000;
  private static final int READ_TIMEOUT_MS = 5_000;

  /** Cached connectivity state — checked once per lookup batch. */
  private volatile Boolean onlineCache = null;
  private volatile long onlineCheckedAt = 0;
  private static final long ONLINE_CHECK_TTL_MS = 60_000; // re-check every 60s

  public record GeoResult(
      String country, String countryCode, String asn, String org,
      String region, String city, Double lat, Double lon, String geoSource) {}

  @PostConstruct
  void init() {
    if (!geoEnabled) {
      log.info("GeoIP enrichment disabled via tracepcap.geo.enabled=false");
      return;
    }
    this.dbReader = tryOpenMmdb();
    if (dbReader == null) {
      log.warn("No GeoIP MMDB file found — offline fallback unavailable. "
          + "Bundle a DB-IP Lite MMDB at /app/geoip/dbip-city-lite.mmdb.");
    } else {
      log.info("GeoIP MMDB loaded successfully (offline fallback ready)");
    }
  }

  @PreDestroy
  void close() {
    if (dbReader != null) {
      try { dbReader.close(); } catch (Exception e) {
        log.warn("Failed to close GeoIP MMDB reader: {}", e.getMessage());
      }
    }
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Returns geo results for all external IPs in the given set.
   * Private/loopback/link-local addresses are silently skipped.
   */
  public Map<String, GeoResult> lookupExternal(Set<String> ips) {
    if (!geoEnabled || ips == null || ips.isEmpty()) return Map.of();

    List<String> external = ips.stream().filter(ip -> !isPrivate(ip)).collect(Collectors.toList());
    if (external.isEmpty()) return Map.of();

    Map<String, GeoResult> result = new HashMap<>();
    Set<String> cachedIps = new HashSet<>();
    List<IpGeoInfoEntity> toRefresh = new ArrayList<>();

    LocalDateTime staleThreshold = LocalDateTime.now().minusDays(CACHE_TTL_DAYS);
    for (IpGeoInfoEntity e : geoInfoRepository.findAllByIpIn(external)) {
      boolean incomplete = e.getLat() == null && e.getCountryCode() != null;
      boolean stale = e.getLookedUpAt() != null && e.getLookedUpAt().isBefore(staleThreshold);
      if (incomplete || stale) {
        toRefresh.add(e);
      } else {
        result.put(e.getIp(), entityToResult(e));
        cachedIps.add(e.getIp());
      }
    }

    // Re-lookup stale/incomplete entries
    if (!toRefresh.isEmpty()) {
      boolean online = isOnline();
      for (IpGeoInfoEntity entity : toRefresh) {
        GeoResult r = online ? lookupFromIpInfo(entity.getIp()) : null;
        if (r == null) r = lookupFromMmdb(entity.getIp());
        if (r != null) {
          updateEntity(entity, r);
          result.put(entity.getIp(), r);
        } else {
          result.put(entity.getIp(), entityToResult(entity));
        }
        cachedIps.add(entity.getIp());
      }
      geoInfoRepository.saveAll(toRefresh);
    }

    // Look up cache misses
    List<String> misses = external.stream()
        .filter(ip -> !cachedIps.contains(ip))
        .collect(Collectors.toList());
    if (!misses.isEmpty()) {
      boolean online = isOnline();
      List<IpGeoInfoEntity> toSave = new ArrayList<>();
      for (String ip : misses) {
        GeoResult r = online ? lookupFromIpInfo(ip) : null;
        if (r == null) r = lookupFromMmdb(ip);
        if (r != null) {
          result.put(ip, r);
          toSave.add(buildEntity(ip, r));
        }
      }
      if (!toSave.isEmpty()) geoInfoRepository.saveAll(toSave);
    }

    return result;
  }

  /** Returns the current geo source being used: "ipinfo" if online, "mmdb" if offline. */
  public String currentSource() {
    return isOnline() ? "ipinfo" : "mmdb";
  }

  // ── ipinfo.io lookup ───────────────────────────────────────────────────────

  private GeoResult lookupFromIpInfo(String ip) {
    try {
      URL url = java.net.URI.create(String.format(IPINFO_URL, ip)).toURL();
      HttpURLConnection conn = (HttpURLConnection) url.openConnection();
      conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
      conn.setReadTimeout(READ_TIMEOUT_MS);
      conn.setRequestProperty("Accept", "application/json");

      if (conn.getResponseCode() != 200) return null;

      JsonNode node;
      try (InputStream is = conn.getInputStream()) {
        node = objectMapper.readTree(is);
      }

      // ipinfo returns "bogon: true" for private IPs — shouldn't happen but guard anyway
      if (node.has("bogon") && node.get("bogon").asBoolean()) return null;

      String countryCode = textOrNull(node, "country");
      String city        = textOrNull(node, "city");
      String region      = textOrNull(node, "region");
      String org         = textOrNull(node, "org"); // e.g. "AS8075 Microsoft Corporation"
      String asn         = null;
      String orgName     = org;

      // org field is "AS#### OrgName" — split into ASN and name
      if (org != null && org.startsWith("AS")) {
        int space = org.indexOf(' ');
        if (space > 0) {
          asn     = org.substring(0, space);
          orgName = org.substring(space + 1);
        }
      }

      // loc is "lat,lon"
      Double lat = null, lon = null;
      String loc = textOrNull(node, "loc");
      if (loc != null && loc.contains(",")) {
        String[] parts = loc.split(",", 2);
        try { lat = Double.parseDouble(parts[0]); lon = Double.parseDouble(parts[1]); }
        catch (NumberFormatException ignored) {}
      }

      // Resolve country name from code
      String country = countryCode != null
          ? new java.util.Locale("", countryCode).getDisplayCountry(java.util.Locale.ENGLISH)
          : null;

      return new GeoResult(country, countryCode, asn, orgName, region, city, lat, lon, "ipinfo");
    } catch (Exception e) {
      log.debug("ipinfo.io lookup failed for {}: {}", ip, e.getMessage());
      return null;
    }
  }

  // ── MMDB lookup ────────────────────────────────────────────────────────────

  private GeoResult lookupFromMmdb(String ip) {
    if (dbReader == null) return null;
    try {
      InetAddress addr = InetAddress.getByName(ip);
      CityResponse resp = dbReader.city(addr);

      String countryCode = resp.getCountry() != null ? resp.getCountry().getIsoCode() : null;
      String country     = resp.getCountry() != null ? resp.getCountry().getName() : null;
      String region      = resp.getMostSpecificSubdivision() != null
          ? resp.getMostSpecificSubdivision().getName() : null;
      String city        = resp.getCity() != null ? resp.getCity().getName() : null;
      Double lat         = resp.getLocation() != null ? resp.getLocation().getLatitude() : null;
      Double lon         = resp.getLocation() != null ? resp.getLocation().getLongitude() : null;

      return new GeoResult(country, countryCode, null, null, region, city, lat, lon, "mmdb");
    } catch (com.maxmind.geoip2.exception.AddressNotFoundException e) {
      return new GeoResult(null, null, null, null, null, null, null, null, "mmdb");
    } catch (Exception e) {
      log.warn("MMDB lookup failed for {}: {}", ip, e.getMessage());
      return null;
    }
  }

  // ── Connectivity check ─────────────────────────────────────────────────────

  private boolean isOnline() {
    long now = System.currentTimeMillis();
    if (onlineCache != null && (now - onlineCheckedAt) < ONLINE_CHECK_TTL_MS) {
      return onlineCache;
    }
    boolean reachable = false;
    HttpURLConnection conn = null;
    try {
      conn = (HttpURLConnection) java.net.URI.create(PROBE_URL).toURL().openConnection();
      conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
      conn.setReadTimeout(CONNECT_TIMEOUT_MS);
      conn.setRequestMethod("HEAD");
      reachable = conn.getResponseCode() < 400;
    } catch (Exception ignored) {
    } finally {
      if (conn != null) conn.disconnect();
    }
    onlineCache = reachable;
    onlineCheckedAt = now;
    log.debug("Internet connectivity check: {}", reachable ? "online (ipinfo.io)" : "offline (MMDB)");
    return reachable;
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private GeoResult entityToResult(IpGeoInfoEntity e) {
    return new GeoResult(e.getCountry(), e.getCountryCode(), e.getAsn(), e.getOrg(),
        e.getRegion(), e.getCity(), e.getLat(), e.getLon(),
        e.getGeoSource() != null ? e.getGeoSource() : "mmdb");
  }

  private void updateEntity(IpGeoInfoEntity entity, GeoResult r) {
    entity.setCountry(r.country());
    entity.setCountryCode(r.countryCode());
    entity.setAsn(r.asn());
    entity.setOrg(r.org());
    entity.setRegion(r.region());
    entity.setCity(r.city());
    entity.setLat(r.lat());
    entity.setLon(r.lon());
    entity.setGeoSource(r.geoSource());
  }

  private IpGeoInfoEntity buildEntity(String ip, GeoResult r) {
    return IpGeoInfoEntity.builder()
        .ip(ip)
        .country(r.country())
        .countryCode(r.countryCode())
        .asn(r.asn())
        .org(r.org())
        .region(r.region())
        .city(r.city())
        .lat(r.lat())
        .lon(r.lon())
        .geoSource(r.geoSource())
        .build();
  }

  private static String textOrNull(JsonNode node, String field) {
    JsonNode n = node.get(field);
    return (n != null && !n.isNull() && !n.asText().isBlank()) ? n.asText() : null;
  }

  private DatabaseReader tryOpenMmdb() {
    if (mmdbPathOverride != null && !mmdbPathOverride.isBlank()) {
      File f = new File(mmdbPathOverride);
      if (f.exists()) return openFile(f);
      log.warn("tracepcap.geo.mmdb-path={} not found", mmdbPathOverride);
    }
    File dockerFile = new File("/app/geoip/dbip-city-lite.mmdb");
    if (dockerFile.exists()) return openFile(dockerFile);
    try (InputStream is = getClass().getClassLoader().getResourceAsStream("geoip/dbip-city-lite.mmdb")) {
      if (is != null) {
        Path tmp = Files.createTempFile("dbip", ".mmdb");
        tmp.toFile().deleteOnExit();
        Files.copy(is, tmp, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        return openFile(tmp.toFile());
      }
    } catch (Exception e) {
      log.debug("Classpath MMDB load failed: {}", e.getMessage());
    }
    return null;
  }

  private DatabaseReader openFile(File f) {
    try {
      return new DatabaseReader.Builder(f).withCache(new CHMCache()).build();
    } catch (Exception e) {
      log.warn("Failed to open GeoIP MMDB {}: {}", f, e.getMessage());
      return null;
    }
  }

  /** Returns true if the IP is RFC1918, loopback, link-local, or IPv6 ULA/loopback. */
  static boolean isPrivate(String ip) {
    if (ip == null || ip.isBlank()) return true;
    String t = ip.trim();
    if (t.equals("::1") || t.startsWith("fc") || t.startsWith("fd") || t.startsWith("fe80"))
      return true;
    if (t.startsWith("10.") || t.startsWith("127.") || t.startsWith("169.254.")
        || t.startsWith("192.168.")) return true;
    if (t.startsWith("172.")) {
      String[] parts = t.split("\\.");
      if (parts.length >= 2) {
        try {
          int second = Integer.parseInt(parts[1]);
          if (second >= 16 && second <= 31) return true;
        } catch (NumberFormatException ignored) {}
      }
    }
    return false;
  }
}
