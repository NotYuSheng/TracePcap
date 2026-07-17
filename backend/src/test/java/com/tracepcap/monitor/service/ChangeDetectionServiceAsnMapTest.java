package com.tracepcap.monitor.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.GeoOrgLookup.IpAttribution;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Regression guard for the ASN identity key (#512 slice 6c review).
 *
 * <p>The map was once keyed {@code asn|org}, which made an ASN's identity depend on its org name: an
 * org enriched from unknown to known between two snapshots presented as a brand-new ASN and raised a
 * spurious ASN_CHANGE. {@link IpAttribution}'s contract is that a null field means "unknown", never
 * "changed" — so the key cannot include a field that may be absent.
 *
 * <p>Not reachable on today's data (every cached ASN happens to carry an org), which is exactly why
 * it needs a test rather than a live check.
 */
class ChangeDetectionServiceAsnMapTest {

  /** asnMap touches none of the collaborators, so nulls are honest here. */
  private final ChangeDetectionService service =
      new ChangeDetectionService(
          null, null, null, null, null, null, null, null, null, null);

  private static Map<String, IpAttribution> geo(IpAttribution... entries) {
    Map<String, IpAttribution> m = new java.util.LinkedHashMap<>();
    for (IpAttribution a : entries) m.put(a.ip(), a);
    return m;
  }

  @Test
  void enrichingAnOrgDoesNotMakeItANewAsn() {
    Map<String, IpAttribution> before =
        geo(new IpAttribution("1.1.1.1", "AS13335", null, "US")); // org not yet known
    Map<String, IpAttribution> after =
        geo(new IpAttribution("1.1.1.1", "AS13335", "Cloudflare, Inc.", "US")); // now enriched

    // Same ASN in both snapshots => nothing added, nothing removed.
    assertThat(service.asnMap(after).keySet()).isEqualTo(service.asnMap(before).keySet());
  }

  @Test
  void anOrgGoingUnknownDoesNotMakeItANewAsn() {
    Map<String, IpAttribution> before =
        geo(new IpAttribution("1.1.1.1", "AS13335", "Cloudflare, Inc.", "US"));
    Map<String, IpAttribution> after = geo(new IpAttribution("1.1.1.1", "AS13335", null, "US"));

    assertThat(service.asnMap(after).keySet()).isEqualTo(service.asnMap(before).keySet());
  }

  @Test
  void keysOnAsnAndKeepsTheFirstAttributionSeen() {
    Map<String, IpAttribution> geoMap =
        geo(
            new IpAttribution("1.1.1.1", "AS13335", "Cloudflare, Inc.", "US"),
            new IpAttribution("1.0.0.1", "AS13335", "Cloudflare", "US"), // same ASN, spelt otherwise
            new IpAttribution("8.8.8.8", "AS15169", "Google LLC", "US"));

    Map<String, IpAttribution> result = service.asnMap(geoMap);

    assertThat(result).containsOnlyKeys("AS13335", "AS15169");
    // First wins, deterministically — a second spelling of the same ASN must not displace it.
    assertThat(result.get("AS13335").org()).isEqualTo("Cloudflare, Inc.");
  }

  @Test
  void attributionsWithoutAnAsnAreSkipped() {
    Map<String, IpAttribution> geoMap =
        geo(
            new IpAttribution("203.0.113.1", null, "Nobody", "ZZ"),
            new IpAttribution("203.0.113.2", "   ", "Nobody", "ZZ"),
            new IpAttribution("8.8.8.8", "AS15169", "Google LLC", "US"));

    assertThat(service.asnMap(geoMap)).containsOnlyKeys("AS15169");
  }
}
