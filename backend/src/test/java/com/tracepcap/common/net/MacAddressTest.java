package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/** The single definition of MAC equality (#733). */
class MacAddressTest {

  @ParameterizedTest
  @ValueSource(
      strings = {
        "aa:bb:cc:dd:ee:ff",
        "AA:BB:CC:DD:EE:FF",
        "aa-bb-cc-dd-ee-ff",
        "AA-BB-CC-DD-EE-FF",
        "aabb.ccdd.eeff",
        "aabbccddeeff",
        "  AA:BB:cc:DD:ee:FF  "
      })
  void everySpellingOfOneAddressNormalisesToTheSameForm(String spelling) {
    // The whole point: a capture, a Cisco config paste and an operator typing by hand produce
    // three different strings for one device.
    assertThat(MacAddress.normalise(spelling)).isEqualTo("aa:bb:cc:dd:ee:ff");
  }

  @Test
  void differentAddressesStayDifferent() {
    assertThat(MacAddress.sameAddress("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:00")).isFalse();
  }

  @Test
  void hyphenAndColonSpellingsCompareEqual() {
    // The exact case that reported a present device as missing from every snapshot.
    assertThat(MacAddress.sameAddress("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff")).isTrue();
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void absentInputIsNullRatherThanAnEmptyKey(String input) {
    // Distinguishable from "an address that normalises to nothing", so a host with no MAC does
    // not collide with another host with no MAC when used as a map key.
    assertThat(MacAddress.normalise(input)).isNull();
  }

  @Test
  void twoAbsentAddressesAreNotTheSameDevice() {
    assertThat(MacAddress.sameAddress(null, null)).isFalse();
  }

  @Test
  void somethingThatIsNotAnAddressIsLeftAloneRatherThanReshaped() {
    // Callers hold operator-typed text. Reshaping "not-a-mac" into a canonical-looking string
    // would invent an address; it only needs to compare equal to itself.
    assertThat(MacAddress.normalise("not-a-mac")).isEqualTo("not-a-mac");
    assertThat(MacAddress.normalise("zz:zz:zz:zz:zz:zz")).isEqualTo("zz:zz:zz:zz:zz:zz");
    assertThat(MacAddress.sameAddress("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", "zz:zz:zz:zz:zz:zz")).isTrue();
  }

  @ParameterizedTest
  @CsvSource({
    "aa:bb:cc:dd:ee:ff, aa:bb:cc",
    "AA-BB-CC-DD-EE-FF, aa:bb:cc",
    "aabb.ccdd.eeff,    aa:bb:cc",
    "aabbccddeeff,      aa:bb:cc"
  })
  void ouiIsTakenFromTheCanonicalFormSoEverySpellingResolvesTheSameVendor(String mac, String oui) {
    assertThat(MacAddress.oui(mac)).isEqualTo(oui);
  }

  @Test
  void ouiIsNullWhenThereIsNotEnoughAddressToHaveOne() {
    assertThat(MacAddress.oui("aa:bb")).isNull();
    assertThat(MacAddress.oui(null)).isNull();
  }
}
