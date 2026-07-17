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
 * <p>The port stays narrower than the underlying row on purpose. The geo cache also stores city,
 * region and coordinates; no module has needed those across the seam, and exposing them "just in
 * case" is how a port becomes a repository. {@link #orgsFor} answers the common question directly;
 * {@link #attributionFor} exists for consumers that must compare ASN or country between snapshots.
 * Add fields when a consumer actually needs them, not before.
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
}
