package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.entity.IpGeoInfoEntity;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The adapter owns the {@code GeoOrgLookup} contract its javadoc advertises — distinct, never null,
 * never blank. These promises used to be filtering inside LabelStalenessService (#512 slice 6b); the
 * seam only holds if the adapter enforces them, because consumers are now entitled to trust them.
 */
class GeoOrgLookupAdapterTest {

  private final IpGeoInfoRepository repository = mock(IpGeoInfoRepository.class);
  private final GeoOrgLookupAdapter adapter = new GeoOrgLookupAdapter(repository);

  private static IpGeoInfoEntity geo(String ip, String org) {
    return IpGeoInfoEntity.builder().ip(ip).org(org).build();
  }

  @Test
  void dropsNullAndBlankOrgsAndDeduplicates() {
    when(repository.findAllByIpIn(anyCollection()))
        .thenReturn(
            List.of(
                geo("1.1.1.1", "Cloudflare, Inc."),
                geo("1.0.0.1", "Cloudflare, Inc."), // duplicate → collapses
                geo("8.8.8.8", null), // no org known → contributes nothing
                geo("9.9.9.9", "   "), // blank → contributes nothing
                geo("66.22.244.154", "i3D.net B.V")));

    assertThat(adapter.orgsFor(Set.of("1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9", "66.22.244.154")))
        .containsExactly("Cloudflare, Inc.", "i3D.net B.V");
  }

  @Test
  void emptyInputShortCircuitsWithoutQuerying() {
    assertThat(adapter.orgsFor(Set.of())).isEmpty();
    verify(repository, never()).findAllByIpIn(anyCollection());
  }

  @Test
  void nullInputIsEmptyNotAnError() {
    // computeProperties can reach here with nothing to resolve; the port promises a list, not a throw.
    assertThat(adapter.orgsFor(null)).isEmpty();
    verify(repository, never()).findAllByIpIn(anyCollection());
  }

  @Test
  void noGeoRecordsYieldsEmptyList() {
    when(repository.findAllByIpIn(anyCollection())).thenReturn(List.of());
    assertThat(adapter.orgsFor(Set.of("10.0.0.1"))).isEmpty();
  }
}
