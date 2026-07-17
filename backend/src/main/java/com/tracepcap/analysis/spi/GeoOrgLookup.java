package com.tracepcap.analysis.spi;

import java.util.Collection;
import java.util.List;

/**
 * Read port for the owning organisations behind a set of IPs (#512 slice 6b), backed by the geo
 * cache.
 *
 * <p>Scoped to orgs on purpose. The geo record also carries country, coordinates and ASN, but the
 * only cross-module question asked of it today is "whose infrastructure did this host talk to?" — a
 * port that exposed the whole geo row would invite the rest back in through the seam.
 */
public interface GeoOrgLookup {

  /**
   * Distinct organisation names known for the given IPs, as a proxy for the external parties
   * contacted. Never null and never contains null or blank entries; IPs with no geo record or no
   * org simply contribute nothing. An empty input yields an empty list.
   */
  List<String> orgsFor(Collection<String> ips);
}
