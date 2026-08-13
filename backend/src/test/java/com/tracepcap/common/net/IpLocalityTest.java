package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The unified locality predicate (#694). These are ordinary tests, not characterisation ones: this
 * is new code with intended behaviour, and the four implementations it replaces are pinned by their
 * own suites so the diff shows exactly which classifications changed.
 */
class IpLocalityTest {

  @ParameterizedTest
  @ValueSource(
      strings = {"10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.1.1"})
  void rfc1918_isLocal(String ip) {
    assertThat(IpLocality.isLocal(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"172.15.255.255", "172.32.0.1", "9.255.255.255", "11.0.0.1"})
  void addressesJustOutsideRfc1918_areNotLocal(String ip) {
    // The boundaries are where prefix matching went wrong before: "172." caught the whole /8.
    assertThat(IpLocality.isLocal(ip)).isFalse();
  }

  @ParameterizedTest
  @ValueSource(strings = {"127.0.0.1", "127.255.255.254", "169.254.1.1", "169.254.255.254"})
  void loopbackAndLinkLocal_areLocal(String ip) {
    // Not routable off-host or off-link, so calling them external puts an address in the "talking
    // to the outside world" bucket that by definition cannot. Two of the four old implementations
    // got this wrong in opposite directions.
    assertThat(IpLocality.isLocal(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"8.8.8.8", "1.1.1.1", "100.64.0.1", "192.169.0.1"})
  void publicAddresses_areNotLocal(String ip) {
    assertThat(IpLocality.isLocal(ip)).isFalse();
  }

  @Test
  void ipv6LoopbackIsLocal() {
    assertThat(IpLocality.isLocal("::1")).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"fc00::1", "fd12:3456::1", "FD12::1", "fdff:ffff::1"})
  void uniqueLocalIpv6_isLocal(String ip) {
    assertThat(IpLocality.isLocal(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"fe80::1", "fe90::1", "fea0::1", "febf::1", "FEBF::1"})
  void theWholeLinkLocalRange_isLocal(String ip) {
    // The headline fix. fe80::/10 spans fe80:: through febf::, but every previous implementation
    // matched the literal string "fe80" — a sixteenth of the range — so febf::1 was reported as
    // a public address.
    assertThat(IpLocality.isLocal(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"fec0::1", "fbff::1", "2001:db8::1", "fe00::1"})
  void ipv6OutsideTheLocalRanges_isNotLocal(String ip) {
    // fec0::/10 is the deprecated site-local range and is deliberately not claimed; fbff:: sits
    // just below fc00::/7. A string-prefix check on "fc"/"fd" would also have caught neither.
    assertThat(IpLocality.isLocal(ip)).isFalse();
  }

  @Test
  void aScopeIdDoesNotChangeTheVerdict() {
    // fe80::1%eth0 is how a link-local address is written with an interface scope.
    assertThat(IpLocality.isLocal("fe80::1%eth0")).isTrue();
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   ", "not-an-ip", "10.0.0", "10.0.0.256", "999.1.1.1", ":"})
  void unparseableInput_isNotLocal(String ip) {
    // Deliberate: an address that cannot be classified must not be claimed as internal. One of
    // the four old implementations treated null as local, silently counting rows with no address
    // as internal traffic. A bare ":" was also accepted as IPv6 by one of them.
    assertThat(IpLocality.isLocal(ip)).isFalse();
  }

  @Test
  void whitespaceIsTolerated() {
    assertThat(IpLocality.isLocal("  10.0.0.1  ")).isTrue();
  }
}
