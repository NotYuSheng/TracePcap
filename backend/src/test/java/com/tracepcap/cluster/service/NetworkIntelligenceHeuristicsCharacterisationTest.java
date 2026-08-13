package com.tracepcap.cluster.service;

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
 * Characterisation tests for {@code NetworkIntelligenceService} (#659, phase 4).
 *
 * <p><b>The address predicate that used to be pinned here is gone, on purpose.</b> This class was
 * written to hold open a divergence: this service and {@code SubnetService} both answered "is this
 * address private" and answered differently, so both behaviours were recorded rather than
 * corrected, precisely so that reconciling them later would be a deliberate change with a visible
 * diff instead of something that happened silently during an extraction.
 *
 * <p>That reconciliation has now happened (#694, then #733). The RFC ranges live in {@code
 * IpLocality} and are tested in {@code IpLocalityTest}; the operator's overrides layered on top
 * live in {@code CustomRangeLocalityPolicy} and are tested there. Keeping a copy of those
 * assertions here would recreate in the tests the duplication the change removed from the code.
 *
 * <p>This is the characterisation test working as designed: it failed loudly when the surface it
 * pinned moved, which is how the move got reviewed rather than noticed later.
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
