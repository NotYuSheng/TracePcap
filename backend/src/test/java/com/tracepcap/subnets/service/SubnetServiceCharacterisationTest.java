package com.tracepcap.subnets.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Characterisation tests for {@code SubnetService}'s address arithmetic (#659, phase 4).
 *
 * <p><b>These pin current behaviour, not desired behaviour.</b> {@code subnets.service} is the
 * least-covered package in the backend — 2,587 instructions at 1.0% — and its subnet detection
 * decides which hosts count as internal, so it shapes every graph drawn from a capture. The point
 * of writing these first is that the extraction step which follows (moving this arithmetic out of
 * an I/O-bound service) then has something to refactor <em>against</em>. Where behaviour looks
 * questionable it is pinned and labelled rather than corrected: changing it here would defeat the
 * purpose.
 *
 * <p>Reached by reflection deliberately. Making the methods package-private to test them would be
 * the very refactor these tests exist to protect, and doing it first is how characterisation
 * suites end up pinning post-refactor behaviour instead of pre-refactor behaviour.
 */
class SubnetServiceCharacterisationTest {

  private static Object invoke(String name, Class<?> paramType, Object arg) {
    try {
      Method m = SubnetService.class.getDeclaredMethod(name, paramType);
      m.setAccessible(true);
      return m.invoke(null, arg);
    } catch (InvocationTargetException e) {
      throw (RuntimeException) e.getCause();
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          name + " is gone or its signature changed — update this characterisation test", e);
    }
  }

  private static long parseIp(String ip) {
    return (long) invoke("parseIp", String.class, ip);
  }

  // --- parseIp ---------------------------------------------------------------

  @ParameterizedTest
  @CsvSource({
    "0.0.0.0, 0",
    "0.0.0.1, 1",
    "0.0.1.0, 256",
    "10.0.0.1, 167772161",
    "192.168.1.1, 3232235777",
    "255.255.255.255, 4294967295"
  })
  void parseIp_packsOctetsBigEndian(String ip, long expected) {
    assertThat(parseIp(ip)).isEqualTo(expected);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "10.0.0", // too few octets
        "10.0.0.1.5", // too many
        "10.0.0.256", // octet out of range
        "10.0.0.-1", // negative octet
        "10.0.0.x", // non-numeric
        "", // empty
        "not-an-ip"
      })
  void parseIp_returnsMinusOneForAnythingMalformed(String ip) {
    // -1 rather than an exception, and -1 is not a reachable packed address, so callers can
    // treat it as a sentinel. Pinned because the extraction is likely to want an Optional and
    // must not change what callers see until they are updated too.
    assertThat(parseIp(ip)).isEqualTo(-1L);
  }

  @Test
  void parseIp_acceptsLeadingZeroesRatherThanTreatingThemAsOctal() {
    // "010" parses as 10, not 8. Worth pinning: some parsers disagree, and a change here would
    // silently move a host between subnets.
    assertThat(parseIp("010.000.000.001")).isEqualTo(parseIp("10.0.0.1"));
  }

  // --- prefixToMask / intToIp ------------------------------------------------

  @ParameterizedTest
  @CsvSource({"0, 0", "8, 4278190080", "16, 4294901760", "24, 4294967040", "32, 4294967295"})
  void prefixToMask_buildsTheContiguousHighBitMask(int prefix, long expected) {
    assertThat((long) invoke("prefixToMask", int.class, prefix)).isEqualTo(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"0.0.0.0", "10.0.0.1", "172.16.5.4", "192.168.1.1", "255.255.255.255"})
  void intToIp_roundTripsWithParseIp(String ip) {
    assertThat(invoke("intToIp", long.class, parseIp(ip))).isEqualTo(ip);
  }

  // --- isPrivate -------------------------------------------------------------

  @ParameterizedTest
  @ValueSource(
      strings = {"10.0.0.1", "10.255.255.255", "192.168.0.1", "172.16.0.1", "172.31.255.255"})
  void isPrivate_acceptsTheThreeRfc1918Blocks(String ip) {
    assertThat(invoke("isPrivate", String.class, ip)).isEqualTo(true);
  }

  @ParameterizedTest
  @ValueSource(strings = {"8.8.8.8", "172.15.0.1", "172.32.0.1", "192.169.0.1", "100.64.0.1"})
  void isPrivate_rejectsPublicAndNearMissRanges(String ip) {
    // 172.15/172.32 sit either side of the RFC1918 block, and 100.64 is CGNAT — near-misses
    // that a looser prefix check would wrongly admit.
    assertThat(invoke("isPrivate", String.class, ip)).isEqualTo(false);
  }

  @ParameterizedTest
  @ValueSource(strings = {"127.0.0.1", "169.254.1.1"})
  void isPrivate_doesNotTreatLoopbackOrLinkLocalAsPrivate(String ip) {
    // Pinned as a known limitation, not endorsed: neither is routable off-host, so classifying
    // them as public is arguably wrong. Changing it would reclassify hosts in existing captures,
    // so it belongs in its own change with its own reasoning — not smuggled in via a refactor.
    assertThat(invoke("isPrivate", String.class, ip)).isEqualTo(false);
  }

  @Test
  void isPrivate_treatsNullAsNotPrivate() {
    assertThat(invoke("isPrivate", String.class, null)).isEqualTo(false);
  }

  // --- normaliseCidr ---------------------------------------------------------

  @ParameterizedTest
  @CsvSource({"10.0.0.0/8, 10.0.0.0/8", "'  192.168.1.0/24  ', 192.168.1.0/24", "0.0.0.0/0, 0.0.0.0/0"})
  void normaliseCidr_trimsAndOtherwisePassesThrough(String input, String expected) {
    // Note it does *not* canonicalise the network address: "10.0.0.5/8" is returned unchanged
    // rather than becoming "10.0.0.0/8". Pinned below.
    assertThat(invoke("normaliseCidr", String.class, input)).isEqualTo(expected);
  }

  @Test
  void normaliseCidr_doesNotZeroTheHostBits() {
    assertThat(invoke("normaliseCidr", String.class, "10.1.2.3/8")).isEqualTo("10.1.2.3/8");
  }

  @ParameterizedTest
  @ValueSource(strings = {"10.0.0.0/33", "10.0.0.0", "10.0.0.256/24", "999.1.1.1/24", "abc/24"})
  void normaliseCidr_rejectsMalformedInput(String cidr) {
    assertThatThrownBy(() -> invoke("normaliseCidr", String.class, cidr))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid CIDR format");
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "   "})
  void normaliseCidr_rejectsBlankWithItsOwnMessage(String cidr) {
    // A different message from the malformed case, so the two are distinguishable in logs.
    assertThatThrownBy(() -> invoke("normaliseCidr", String.class, cidr))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not be blank");
  }
}
