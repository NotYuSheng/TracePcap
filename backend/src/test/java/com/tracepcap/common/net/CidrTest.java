package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** One way to write a CIDR for every settings list (#1351). */
class CidrTest {

  @ParameterizedTest
  @CsvSource({
    "10.0.0.0/8, 10.0.0.0/8",
    "' 10.1.2.3/8 ', 10.0.0.0/8", // the network it names
    "192.168.1.77/24, 192.168.1.0/24",
    "10.0.0.5, 10.0.0.5/32", // a bare address is that one host
    "0.0.0.0/0, 0.0.0.0/0",
    "fd00::/8, fd00:0:0:0:0:0:0:0/8", // Java's long form, as custom ranges are stored
    "fd12:3456::1/64, fd12:3456:0:0:0:0:0:0/64",
    "2001:db8::1, 2001:db8:0:0:0:0:0:1/128",
  })
  void savesTheNetworkACidrNames(String raw, String expected) {
    assertThat(Cidr.normalise(raw)).isEqualTo(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"10.0.0.0/33", "fd00::/129", "10.0.0.256/24", "10.1/8", "example.com/24",
      "localhost", "10.0.0.0/-1", "10.0.0.0/", "10.0.0.0/8/8", "::ffff:10.0.0.1/104"})
  void rejectsWhatIsntALiteralCidr(String raw) {
    // "10.1" would be 10.0.0.1 to InetAddress; a name would be a DNS lookup. Neither is allowed.
    assertThatThrownBy(() -> Cidr.normalise(raw))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Invalid CIDR");
  }

  @Test
  void blankHasItsOwnMessage() {
    assertThatThrownBy(() -> Cidr.normalise("  ")).hasMessage("A CIDR is required");
    assertThatThrownBy(() -> Cidr.normalise(null)).hasMessage("A CIDR is required");
  }

  @Test
  void tellsIpv4FromIpv6() {
    assertThat(Cidr.isIpv4(Cidr.normalise("10.0.0.0/8"))).isTrue();
    assertThat(Cidr.isIpv4(Cidr.normalise("fd00::/8"))).isFalse();
  }

  @Test
  void aStoredCidrIsComparedByTheNetworkItNames() {
    assertThat(Cidr.same("fd00::/8", "fd00:0:0:0:0:0:0:0/8")).isTrue();
    assertThat(Cidr.same("10.1.2.3/24", "10.1.2.0/24")).isTrue();
    assertThat(Cidr.same("10.1.2.0/24", "10.1.3.0/24")).isFalse();
    assertThat(Cidr.same(null, "10.0.0.0/8")).isFalse();
    // A row saved from free text before #1351 is kept as it was: never a match for a real CIDR.
    assertThat(Cidr.key(" gw.corp/24 ")).isEqualTo("gw.corp/24");
    assertThat(Cidr.same("gw.corp/24", "10.0.0.0/24")).isFalse();
  }
}
