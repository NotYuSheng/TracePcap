package com.tracepcap.monitor.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.intelligence.service.CustomPrivateRangeService;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Characterisation tests for {@code ChangeDetectionService}'s locality predicate (#659, phase 4).
 * Fourth slice, after {@code subnets.service} (#688), {@code report} (#690) and {@code
 * intelligence.service} (#692).
 *
 * <p><b>This is the third definition of "private" in the codebase</b>, and the widest. Tracked as
 * #694, which the first two slices opened. The divergences pinned here are the sharpest yet:
 *
 * <ul>
 *   <li>It accepts {@code 169.254/16} link-local, which the other two reject.
 *   <li>It returns <b>true</b> for a null address. The other two return false. So a missing address
 *       counts as internal on this path and external on both others.
 * </ul>
 *
 * <p>Neither is corrected here. Pinning all three is what makes unifying them a change with a
 * visible diff rather than a silent reclassification of existing captures.
 *
 * <p>Unlike the earlier slices this method has a collaborator, so the range service is stubbed to
 * "no override, no custom CIDR" — isolating the built-in heuristic, which is the part that diverges.
 */
class ChangeDetectionLocalityCharacterisationTest {

  private static final ChangeDetectionService SERVICE = serviceWithNeutralRangeService();

  private static ChangeDetectionService serviceWithNeutralRangeService() {
    try {
      Constructor<?> ctor = ChangeDetectionService.class.getDeclaredConstructors()[0];
      ctor.setAccessible(true);
      ChangeDetectionService service =
          (ChangeDetectionService) ctor.newInstance(new Object[ctor.getParameterCount()]);

      CustomPrivateRangeService ranges = mock(CustomPrivateRangeService.class);
      when(ranges.overrideFor(any(), any()))
          .thenReturn(CustomPrivateRangeService.Override.NONE);
      when(ranges.isInCidrs(any(), any())).thenReturn(false);

      Field field = ChangeDetectionService.class.getDeclaredField("customPrivateRangeService");
      field.setAccessible(true);
      field.set(service, ranges);
      return service;
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          "ChangeDetectionService's shape changed — update this characterisation test", e);
    }
  }

  private static boolean isPrivate(String ip) {
    try {
      // LocalityRules is a private record nested in ChangeDetectionService.
      Class<?> rulesType =
          Class.forName("com.tracepcap.monitor.service.ChangeDetectionService$LocalityRules");
      Method m = ChangeDetectionService.class.getDeclaredMethod("isPrivate", String.class, rulesType);
      m.setAccessible(true);
      Constructor<?> rulesCtor = rulesType.getDeclaredConstructors()[0];
      rulesCtor.setAccessible(true);
      Object rules = rulesCtor.newInstance(new Object[rulesCtor.getParameterCount()]);
      return (boolean) m.invoke(SERVICE, ip, rules);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("isPrivate/LocalityRules changed — update this test", e);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.0.1", "127.0.0.1", "::1"})
  void isPrivate_acceptsRfc1918AndLoopback(String ip) {
    assertThat(isPrivate(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"fc00::1", "fd00::1", "fe80::1"})
  void isPrivate_acceptsIpv6UniqueLocalAndLinkLocal(String ip) {
    // fe80::/10 is IPv6 link-local. Note the IPv4 equivalent (169.254) is accepted here too but
    // rejected by both other implementations — see below.
    assertThat(isPrivate(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"169.254.1.1", "169.254.255.255"})
  void isPrivate_acceptsIpv4LinkLocal_unlikeTheOtherTwoImplementations(String ip) {
    // SubnetService.isPrivate and NetworkIntelligenceService.isPrivateIp both return false for
    // these. Pinned on all three sides so #694 can reconcile them deliberately.
    assertThat(isPrivate(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"8.8.8.8", "172.15.0.1", "172.32.0.1", "100.64.0.1", "2001:db8::1"})
  void isPrivate_rejectsPublicAndNearMissRanges(String ip) {
    assertThat(isPrivate(ip)).isFalse();
  }

  @ParameterizedTest
  @NullSource
  void isPrivate_nowTreatsNullAsNotPrivate_matchingTheOthers(String ip) {
    // Changed by #694. This service alone answered true, so a row with no address counted as
    // internal traffic. The other three all treated an unclassifiable address as not-private.
    assertThat(isPrivate(ip)).isFalse();
  }

  @Test
  void isPrivate_nowCoversTheWholeFe80Slash10LinkLocalRange() {
    // Fixed by #694, and the clearest case for parsing over prefix matching: fe80::/10 spans
    // fe80:: through febf::, but a literal "fe80" string prefix matched a sixteenth of it, so
    // febf::1 — link-local — was classified as a public address.
    assertThat(isPrivate("fe80::1")).isTrue();
    assertThat(isPrivate("febf::1")).isTrue();
  }

  @Test
  void isPrivate_matchesFePrefixOnlyForFe80NotAllFeAddresses() {
    // The prefix set contains "fe80" rather than "fe", so fec0:: (deprecated site-local) is not
    // matched. Worth pinning: the neighbouring fc/fd entries are two characters, and it would be
    // easy to "tidy" this one to match.
    assertThat(isPrivate("fec0::1")).isFalse();
  }
}
