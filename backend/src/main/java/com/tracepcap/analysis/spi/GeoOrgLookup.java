package com.tracepcap.analysis.spi;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Read port for what is known about the parties behind a set of IPs (#512 slices 6b/6c), backed by
 * the geo cache.
 *
 * <p>Everything here is <b>INFERRED</b>: a third-party database's opinion about who owns an address
 * range. It is not measured, it is not testimony from the host, and it goes stale as ranges are
 * reassigned. Consumers should weigh it accordingly.
 *
 * <p>Three shapes, widening only as a consumer has actually needed them:
 *
 * <ul>
 *   <li>{@link #orgsFor} — just the names. "Whose infrastructure did this host talk to?"
 *   <li>{@link #attributionFor} — ASN, org, country. Enough to tell a real gateway change from
 *       noise when comparing two snapshots.
 *   <li>{@link #placesFor} — adds city and coordinates, for consumers that group hosts
 *       geographically. Widest, and deliberately the last resort.
 * </ul>
 *
 * Three methods rather than one full record, because the narrow answers stay cheap to reason about:
 * a caller comparing ASNs has no business holding a latitude.
 */
public interface GeoOrgLookup {

  /**
   * Who an IP is attributed to. Every field may be null — the cache may hold no record for an IP, or
   * a partial one — so a consumer comparing these must treat null as "unknown", never as "changed".
   */
  record IpAttribution(String ip, String asn, String org, String countryCode) {}

  /**
   * Distinct organisation names known for the given IPs, as a proxy for the external parties
   * contacted. Never null and never contains null or blank entries; IPs with no geo record or no org
   * simply contribute nothing. An empty input yields an empty list.
   */
  List<String> orgsFor(Collection<String> ips);

  /**
   * Attribution for each of the given IPs that has a geo record, keyed by IP.
   *
   * <p>IPs with no record are absent from the map rather than mapped to a null or empty value — the
   * caller asked what is known, and nothing is known about those. An empty input yields an empty
   * map.
   */
  Map<String, IpAttribution> attributionFor(Collection<String> ips);

  /**
   * Where an IP is believed to be, for consumers that group hosts geographically.
   *
   * <p>{@code geoSource} names which database answered (the online lookup or the bundled offline
   * MMDB) — it is provenance, not location, and consumers surface it so a user can judge the claim.
   * Every other field may be null, and coordinates are a coarse range centroid: they locate the
   * <em>registration</em>, never the device.
   */
  record IpPlace(
      String ip,
      String asn,
      String org,
      String countryCode,
      String country,
      String city,
      Double lat,
      Double lon,
      String geoSource) {}

  /**
   * Places for each of the given IPs that has a geo record, keyed by IP. IPs with no record are
   * absent rather than mapped to an empty value; an empty input yields an empty map.
   */
  Map<String, IpPlace> placesFor(Collection<String> ips);

  /** A country as the geo database names it. */
  record Country(String code, String name) {}

  /**
   * The distinct countries any endpoint in a file resolves to, ordered by name — for populating a
   * country filter.
   *
   * <p>Countries with no code are omitted: a filter entry nothing can match is noise. Typed rather
   * than the {@code Object[]} the projection yields, so callers don't index into a SELECT list.
   */
  List<Country> distinctCountriesInFile(java.util.UUID fileId);
}
