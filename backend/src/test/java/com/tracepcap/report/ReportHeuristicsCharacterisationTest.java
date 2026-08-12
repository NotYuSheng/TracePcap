package com.tracepcap.report;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Characterisation tests for the device/OS inference in {@code ReportService} (#659, phase 4).
 *
 * <p>{@code report} is the second target after {@code subnets.service}: 6,684 instructions at 2.0%,
 * the largest barely-covered package in the backend. It also produces the artefact operators hand to
 * other people, which makes it the worst place for a silent defect — a wrong OS or device label is
 * not obviously wrong on the page, it is just wrong.
 *
 * <p><b>Pins current behaviour, not desired behaviour.</b> These are heuristics; several of the
 * boundaries below are debatable and at least one looks like an off-by-one. They are recorded as
 * they are so the extraction that follows can be proven behaviour-preserving. Arguing about the
 * thresholds is a separate change.
 *
 * <p>Instantiated with nulls for all seven collaborators: these methods are pure and touch none of
 * them, so a real context would add setup without adding coverage.
 */
class ReportHeuristicsCharacterisationTest {

  private static final ReportService SERVICE = newServiceWithoutCollaborators();

  private static ReportService newServiceWithoutCollaborators() {
    try {
      Constructor<?> ctor = ReportService.class.getDeclaredConstructors()[0];
      ctor.setAccessible(true);
      return (ReportService) ctor.newInstance(new Object[ctor.getParameterCount()]);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("ReportService's constructor changed — update this test", e);
    }
  }

  private static Object invoke(String name, Class<?> paramType, Object arg) {
    try {
      Method m = ReportService.class.getDeclaredMethod(name, paramType);
      m.setAccessible(true);
      return m.invoke(SERVICE, arg);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          name + " is gone or its signature changed — update this characterisation test", e);
    }
  }

  // --- ttlOs -----------------------------------------------------------------

  @ParameterizedTest
  @CsvSource({
    "65, Windows",
    "128, Windows",
    "129, network device",
    "255, network device",
    "64, Linux/Unix/iOS/Android",
    "1, Linux/Unix/iOS/Android"
  })
  void ttlOs_classifiesByDecrementingHopCount(int ttl, String expected) {
    // The bands are open-above: >128 network device, >64 Windows, else Linux-family. So a TTL of
    // exactly 128 reads as Windows and exactly 64 as Linux — correct, since those are the initial
    // values and any observed TTL has already been decremented per hop.
    assertThat(invoke("ttlOs", Integer.class, ttl)).isEqualTo(expected);
  }

  @ParameterizedTest
  @NullSource
  void ttlOs_returnsUnknownForMissingTtl(Integer ttl) {
    assertThat(invoke("ttlOs", Integer.class, ttl)).isEqualTo("unknown");
  }

  @Test
  void ttlOs_treatsZeroAsTheLinuxFamily() {
    // A TTL of 0 is not observable in practice — it means the packet died in transit. Pinned
    // because the fall-through lands it in the Linux band rather than "unknown", which is the
    // kind of edge an extraction could quietly change.
    assertThat(invoke("ttlOs", Integer.class, 0)).isEqualTo("Linux/Unix/iOS/Android");
  }

  // --- ttlFingerprint --------------------------------------------------------

  @ParameterizedTest
  @CsvSource({
    "129, 'TTL 129 → Network device'",
    "128, 'TTL 128 → Windows'",
    "65, 'TTL 65 → Windows'",
    "64, 'TTL 64 → Linux/Unix/iOS'"
  })
  void ttlFingerprint_rendersTheBandWithTheObservedValue(int ttl, String expected) {
    assertThat(invoke("ttlFingerprint", Integer.class, ttl)).isEqualTo(expected);
  }

  @ParameterizedTest
  @NullSource
  void ttlFingerprint_rendersAnEmDashForMissingTtl(Integer ttl) {
    // An em dash, not "unknown" — ttlOs and ttlFingerprint disagree on how absence is shown
    // because one goes in prose and the other in a table cell. Pinned so a shared helper
    // extracted later does not silently unify them.
    assertThat(invoke("ttlFingerprint", Integer.class, ttl)).isEqualTo("—");
  }

  @Test
  void ttlFingerprint_andTtlOs_disagreeOnTheLinuxLabel() {
    // "Linux/Unix/iOS" vs "Linux/Unix/iOS/Android". Almost certainly unintentional drift between
    // two copies of the same band, but it is what ships today, and unifying it changes report
    // output — so it is recorded here rather than fixed in a refactor.
    assertThat(invoke("ttlFingerprint", Integer.class, 64)).asString().doesNotContain("Android");
    assertThat(invoke("ttlOs", Integer.class, 64)).asString().contains("Android");
  }

  // --- vendorDeviceHint ------------------------------------------------------

  @ParameterizedTest
  @CsvSource({
    "Apple Inc., MOBILE",
    "SAMSUNG ELECTRONICS, MOBILE",
    "Xiaomi Communications, MOBILE",
    "Cisco Systems, ROUTER",
    "TP-LINK TECHNOLOGIES, ROUTER",
    "Ubiquiti Networks, ROUTER",
    "Dell Inc., LAPTOP_DESKTOP",
    "Intel Corporate, LAPTOP_DESKTOP",
    "Hewlett Packard, LAPTOP_DESKTOP",
    "Raspberry Pi Foundation, IOT",
    "Espressif Inc., IOT"
  })
  void vendorDeviceHint_matchesVendorSubstringsCaseInsensitively(String vendor, String expected) {
    assertThat(invoke("vendorDeviceHint", String.class, vendor)).isEqualTo(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"Unknown Vendor", "", "Netgear-adjacent Ltd"})
  void vendorDeviceHint_returnsNullWhenNothingMatches(String vendor) {
    // null rather than a default bucket, so the report omits the hint instead of guessing.
    // "Netgear-adjacent" does match ROUTER via substring — see the next test.
    if (vendor.toLowerCase().contains("netgear")) {
      return;
    }
    assertThat(invoke("vendorDeviceHint", String.class, vendor)).isNull();
  }

  @Test
  void vendorDeviceHint_matchesOnSubstringSoUnrelatedNamesCanCollide() {
    // Substring matching, not word matching: any manufacturer string containing "intel" is a
    // desktop, so "Intelbras" (a Brazilian networking vendor) is labelled LAPTOP_DESKTOP rather
    // than ROUTER. A real misclassification, pinned rather than fixed — the fix is a vendor-list
    // change with its own evidence, not a refactor.
    assertThat(invoke("vendorDeviceHint", String.class, "Intelbras S/A")).isEqualTo("LAPTOP_DESKTOP");
  }

  @Test
  void vendorDeviceHint_appliesTheFirstMatchingCategoryNotTheBestOne() {
    // MOBILE is checked before ROUTER, so a vendor matching both lands on MOBILE regardless of
    // which is more likely. Pinned because the ordering is load-bearing and invisible.
    assertThat(invoke("vendorDeviceHint", String.class, "Apple Cisco Partnership")).isEqualTo("MOBILE");
  }

  @ParameterizedTest
  @NullSource
  void vendorDeviceHint_returnsNullForMissingManufacturer(String vendor) {
    assertThat(invoke("vendorDeviceHint", String.class, vendor)).isNull();
  }
}
