package com.tracepcap.intelligence.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Characterisation tests for {@code NetworkIntelligenceService}'s address predicates (#659, phase
 * 4). Third slice, after {@code subnets.service} (#688) and {@code report} (#690).
 *
 * <p><b>The headline finding is the divergence.</b> This service and {@code SubnetService} both
 * answer "is this address private", and they answer differently. {@code SubnetService.isPrivate}
 * covers only the three RFC1918 blocks; the version here also accepts loopback and IPv6 unique-local
 * addresses. So the same host can count as internal on one code path and external on another, which
 * changes how a capture is summarised depending on which path produced the summary.
 *
 * <p>Both behaviours are pinned — here and in {@code SubnetServiceCharacterisationTest} — precisely
 * so that reconciling them later is a deliberate change with a visible diff, rather than something
 * that silently happens during an extraction. Neither is corrected here.
 */
class NetworkIntelligenceHeuristicsCharacterisationTest {

  private static final NetworkIntelligenceService SERVICE = newServiceWithoutCollaborators();

  private static NetworkIntelligenceService newServiceWithoutCollaborators() {
    try {
      Constructor<?> ctor = NetworkIntelligenceService.class.getDeclaredConstructors()[0];
      ctor.setAccessible(true);
      return (NetworkIntelligenceService) ctor.newInstance(new Object[ctor.getParameterCount()]);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          "NetworkIntelligenceService's constructor changed — update this test", e);
    }
  }

  private static Object invoke(String name, Class<?> paramType, Object arg) {
    try {
      Method m = NetworkIntelligenceService.class.getDeclaredMethod(name, paramType);
      m.setAccessible(true);
      return m.invoke(SERVICE, arg);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          name + " is gone or its signature changed — update this characterisation test", e);
    }
  }

  private static boolean isPrivateIp(String ip) {
    return (boolean) invoke("isPrivateIp", String.class, ip);
  }

  // --- isPrivateIp -----------------------------------------------------------

  @ParameterizedTest
  @ValueSource(
      strings = {"10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.255", "172.20.10.5"})
  void isPrivateIp_acceptsTheRfc1918Blocks(String ip) {
    assertThat(isPrivateIp(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"127.0.0.1", "127.255.255.254"})
  void isPrivateIp_alsoAcceptsIpv4Loopback(String ip) {
    // Diverges from SubnetService.isPrivate, which returns false for loopback (pinned in
    // SubnetServiceCharacterisationTest). Recorded on both sides so reconciling them is a
    // deliberate change rather than a silent one.
    assertThat(isPrivateIp(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"::1", "fc00::1", "fd12:3456::1", "FD12::1", "FC00::1"})
  void isPrivateIp_acceptsIpv6LoopbackAndUniqueLocal(String ip) {
    // fc00::/7 is the IPv6 ULA range; the check is a case-insensitive "fc"/"fd" prefix.
    assertThat(isPrivateIp(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"8.8.8.8", "172.15.0.1", "172.32.0.1", "100.64.0.1", "2001:db8::1"})
  void isPrivateIp_rejectsPublicAndNearMissRanges(String ip) {
    assertThat(isPrivateIp(ip)).isFalse();
  }

  @ParameterizedTest
  @ValueSource(strings = {"169.254.1.1"})
  void isPrivateIp_nowAcceptsIpv4LinkLocal(String ip) {
    // Changed by #694. All four implementations previously agreed that 169.254/16 was public,
    // which was consistently wrong rather than divergent: it is not routable off-link.
    assertThat(isPrivateIp(ip)).isTrue();
  }

  @Test
  void isPrivateIp_matchesFcAndFdByPrefixSoSomeGlobalAddressesCollide() {
    // The prefix test is on the raw string, not a parsed address, so any address whose text
    // starts with "fc"/"fd" is private — including "fcda::1" style addresses outside fc00::/7
    // in a stricter reading. Pinned because a parsed implementation would answer differently.
    assertThat(isPrivateIp("fcff::1")).isTrue();
  }

  @ParameterizedTest
  @NullSource
  void isPrivateIp_treatsNullAsNotPrivate(String ip) {
    assertThat(isPrivateIp(ip)).isFalse();
  }

  @Test
  void isPrivateIp_isCaseSensitiveForIpv4ButNotIpv6() {
    // "10." and "192.168." are compared as-is while the IPv6 prefixes are lowercased first.
    // Harmless for IPv4 (digits have no case) but worth pinning as the asymmetry it is.
    assertThat(isPrivateIp("FD00::1")).isTrue();
    assertThat(isPrivateIp("fd00::1")).isTrue();
  }

  // --- splitResolvedIps ------------------------------------------------------

  @ParameterizedTest
  @CsvSource({
    "'10.0.0.1,10.0.0.2', 2",
    "'10.0.0.1', 1",
    "'10.0.0.1, 10.0.0.2 , 10.0.0.3', 3",
    "'10.0.0.1,,10.0.0.2', 2",
    "',,,', 0"
  })
  @SuppressWarnings("unchecked")
  void splitResolvedIps_trimsAndDropsEmptyEntries(String joined, int expected) {
    // DNS answers arrive as one comma-joined column. An empty entry would become a lookup for
    // "" downstream, so dropping them here is load-bearing rather than cosmetic.
    List<String> result = (List<String>) invoke("splitResolvedIps", String.class, joined);
    assertThat(result).hasSize(expected).allSatisfy(s -> assertThat(s).isNotBlank());
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {"", "   "})
  @SuppressWarnings("unchecked")
  void splitResolvedIps_returnsEmptyForNullOrBlank(String joined) {
    assertThat((List<String>) invoke("splitResolvedIps", String.class, joined)).isEmpty();
  }
}
