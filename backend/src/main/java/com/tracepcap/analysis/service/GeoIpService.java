package com.tracepcap.analysis.service;

import com.maxmind.db.CHMCache;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Enriches external (non-RFC1918) IP addresses with country, region, city, and ASN information
 * using an offline MaxMind GeoIP2 / DB-IP Lite MMDB database.
 *
 * <p>The database file is resolved in this order:
 *
 * <ol>
 *   <li>{@code tracepcap.geo.mmdb-path} property (absolute path, useful for Docker volume mounts)
 *   <li>{@code /app/geoip/dbip-city-lite.mmdb} — default Docker image location
 *   <li>Classpath resource {@code geoip/dbip-city-lite.mmdb} — bundled in the image
 * </ol>
 *
 * <p>Results are cached in the {@code ip_geo_cache} table so repeated analyses never re-lookup an
 * already-known IP. If the MMDB file is absent, geo enrichment is silently skipped.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GeoIpService {

  @Value("${tracepcap.geo.enabled:true}")
  private boolean geoEnabled;

  /** Optional override path for the MMDB file. */
  @Value("${tracepcap.geo.mmdb-path:}")
  private String mmdbPathOverride;

  private final IpGeoInfoRepository geoInfoRepository;

  private DatabaseReader dbReader;

  public record GeoResult(
      String country, String countryCode, String asn, String org,
      String region, String city, Double lat, Double lon) {}

  @PostConstruct
  void init() {
    if (!geoEnabled) {
      log.info("GeoIP enrichment disabled via tracepcap.geo.enabled=false");
      return;
    }

    DatabaseReader reader = tryOpenMmdb();
    if (reader == null) {
      log.warn(
          "No GeoIP MMDB file found — geo enrichment will be skipped. "
              + "Bundle a DB-IP Lite MMDB at /app/geoip/dbip-city-lite.mmdb in the Docker image.");
    } else {
      log.info("GeoIP database loaded successfully");
    }
    this.dbReader = reader;
  }

  private DatabaseReader tryOpenMmdb() {
    // 1. Explicit override path
    if (mmdbPathOverride != null && !mmdbPathOverride.isBlank()) {
      File f = new File(mmdbPathOverride);
      if (f.exists()) {
        return openFile(f);
      }
      log.warn("tracepcap.geo.mmdb-path={} not found", mmdbPathOverride);
    }

    // 2. Default Docker location
    File dockerFile = new File("/app/geoip/dbip-city-lite.mmdb");
    if (dockerFile.exists()) {
      return openFile(dockerFile);
    }

    // 3. Classpath
    try (InputStream is =
        getClass().getClassLoader().getResourceAsStream("geoip/dbip-city-lite.mmdb")) {
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

  /**
   * Given a set of IP strings, returns a map of IP → GeoResult for all external IPs. Private,
   * loopback, and link-local addresses are silently skipped.
   */
  public Map<String, GeoResult> lookupExternal(Set<String> ips) {
    if (!geoEnabled || dbReader == null || ips == null || ips.isEmpty()) return Map.of();

    List<String> external = ips.stream().filter(ip -> !isPrivate(ip)).collect(Collectors.toList());
    if (external.isEmpty()) return Map.of();

    // Load cached entries
    Map<String, GeoResult> result = new HashMap<>();
    List<IpGeoInfoEntity> cached = geoInfoRepository.findAllByIpIn(external);
    Set<String> cachedIps = new HashSet<>();
    for (IpGeoInfoEntity e : cached) {
      result.put(
          e.getIp(),
          new GeoResult(
              e.getCountry(), e.getCountryCode(), e.getAsn(), e.getOrg(),
              e.getRegion(), e.getCity(), e.getLat(), e.getLon()));
      cachedIps.add(e.getIp());
    }

    // Lookup cache misses from MMDB
    List<String> misses =
        external.stream().filter(ip -> !cachedIps.contains(ip)).collect(Collectors.toList());
    if (!misses.isEmpty()) {
      Map<String, GeoResult> fetched = lookupFromMmdb(misses);
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
                          .region(e.getValue().region())
                          .city(e.getValue().city())
                          .lat(e.getValue().lat())
                          .lon(e.getValue().lon())
                          .build())
              .collect(Collectors.toList());
      if (!toSave.isEmpty()) {
        geoInfoRepository.saveAll(toSave);
      }
    }

    return result;
  }

  private Map<String, GeoResult> lookupFromMmdb(List<String> ips) {
    Map<String, GeoResult> result = new HashMap<>();
    for (String ip : ips) {
      try {
        InetAddress addr = InetAddress.getByName(ip);
        CityResponse resp = dbReader.city(addr);

        String countryCode =
            resp.getCountry() != null ? resp.getCountry().getIsoCode() : null;
        String country =
            resp.getCountry() != null ? resp.getCountry().getName() : null;
        String region =
            resp.getMostSpecificSubdivision() != null
                ? resp.getMostSpecificSubdivision().getName()
                : null;
        String city =
            resp.getCity() != null ? resp.getCity().getName() : null;
        Double lat =
            resp.getLocation() != null ? resp.getLocation().getLatitude() : null;
        Double lon =
            resp.getLocation() != null ? resp.getLocation().getLongitude() : null;

        // DB-IP Lite does not include ASN — leave null (ASN data requires a separate DB)
        result.put(ip, new GeoResult(country, countryCode, null, null, region, city, lat, lon));
      } catch (com.maxmind.geoip2.exception.AddressNotFoundException e) {
        // IP not in DB — cache as empty to avoid retrying
        result.put(ip, new GeoResult(null, null, null, null, null, null, null, null));
      } catch (Exception e) {
        log.debug("GeoIP MMDB lookup failed for {}: {}", ip, e.getMessage());
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
}
