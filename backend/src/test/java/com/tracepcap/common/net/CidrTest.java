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
    "fd00::/8, fd00::/8", // RFC 5952, as typed
    "fd12:3456::1/64, fd12:3456::/64",
    "FD00:0:0:0:0:0:0:0/8, fd00::/8", // a long or upper-case spelling of the same network
    "2001:db8:0:0:1:0:0:1/128, 2001:db8::1:0:0:1/128", // the first of two equal zero runs
    "2001:db8::1, 2001:db8::1/128",
    "::1, ::1/128",
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
  void aStoredCidrIsWrittenAsASaveWouldWriteIt() {
    assertThat(Cidr.key("10.1.2.3/24")).isEqualTo("10.1.2.0/24");
    assertThat(Cidr.key("fd00:0:0:0:0:0:0:0/8")).isEqualTo("fd00::/8");
    // Free text an older validator let through is only trimmed.
    assertThat(Cidr.key(" gw.corp/24 ")).isEqualTo("gw.corp/24");
  }

  @Test
  void subnetListsAreIpv4ForNow() {
    assertThat(Cidr.normaliseIpv4("10.1.2.3/24")).isEqualTo("10.1.2.0/24");
    assertThatThrownBy(() -> Cidr.normaliseIpv4("fd00::/64")).hasMessageContaining("IPv4 for now");
  }

  @Test
  void aSpellingSentBackExactlyAsSavedIsKept_anythingNewIsNormalised() {
    java.util.Set<String> saved = java.util.Set.of("10.62.0.9/24", "10.0.0.01/24");
    // A row V86 left in its old spelling: still the same entry when the list sends it back.
    assertThat(Cidr.asSaved(" 10.62.0.9/24 ", saved, Cidr::normaliseIpv4)).isEqualTo("10.62.0.9/24");
    assertThat(Cidr.asSaved("10.0.0.01/24", saved, Cidr::normaliseIpv4)).isEqualTo("10.0.0.01/24");
    assertThat(Cidr.asSaved("10.63.0.9/24", saved, Cidr::normaliseIpv4)).isEqualTo("10.63.0.0/24");
    assertThatThrownBy(() -> Cidr.asSaved("10.0.0.02/24", saved, Cidr::normaliseIpv4))
        .hasMessageStartingWith("Invalid CIDR");
  }

  @Test
  void aNumericLiteralNeverNeedsADnsLookup() {
    assertThat(Cidr.isNumericLiteral("10.0.0.01")).isTrue(); // an old row the matchers still read
    assertThat(Cidr.isNumericLiteral("fd00::1")).isTrue();
    assertThat(Cidr.isNumericLiteral("gw.corp")).isFalse();
    assertThat(Cidr.isNumericLiteral("dead.beef")).isFalse(); // hex letters, but a name to InetAddress
    assertThat(Cidr.isNumericLiteral(" ")).isFalse();
  }
}
