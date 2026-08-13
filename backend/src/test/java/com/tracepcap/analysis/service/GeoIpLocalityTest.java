package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The fifth "is this address local" implementation (#733 finding 1), now delegating to
 * {@link com.tracepcap.common.net.IpLocality} for the range test.
 *
 * <p>It keeps two answers the shared predicate deliberately does not give — {@code null} and MAC
 * addresses are skipped — because this method never answered "is this private". It answers "is
 * there any point looking this up", and sharing a name with the range test while disagreeing with
 * it on those inputs is what kept the duplication invisible.
 */
class GeoIpLocalityTest {

  @ParameterizedTest
  @ValueSource(strings = {"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1"})
  void rfc1918AndFriendsAreSkipped(String ip) {
    assertThat(GeoIpService.shouldSkipLookup(ip)).isTrue();
  }

  @ParameterizedTest
  @NullAndEmptySource
  void absentAddressesAreSkipped(String ip) {
    assertThat(GeoIpService.shouldSkipLookup(ip)).isTrue();
  }

  @Test
  void macAddressesAreSkipped() {
    assertThat(GeoIpService.shouldSkipLookup("00:11:22:33:44:55")).isTrue();
  }

  @Test
  void publicAddressesAreLookedUp() {
    assertThat(GeoIpService.shouldSkipLookup("8.8.8.8")).isFalse();
  }

  // --- two defects the local copy had, fixed by delegating -------------------

  @ParameterizedTest
  @ValueSource(strings = {"fe80::1", "feb0::1", "febf::1"})
  void allOfTheLinkLocalRangeIsSkipped(String ip) {
    // Was startsWith("fe80"), which matched one hextet of fe80::/10, so feb0::1 was sent to an
    // external lookup. The wasted call is not the problem — leaking internal addressing to a
    // third party is.
    assertThat(GeoIpService.shouldSkipLookup(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"fc00::1", "FC00::1", "fd12:3456::1", "FD12:3456::1"})
  void uniqueLocalIsSkippedWhateverTheCase(String ip) {
    // The local copy never lowercased, so an uppercase ULA was treated as public.
    assertThat(GeoIpService.shouldSkipLookup(ip)).isTrue();
  }

  @Test
  void aGenuinelyExternalIpv6AddressIsStillLookedUp() {
    assertThat(GeoIpService.shouldSkipLookup("2001:db8::1")).isFalse();
  }
}
