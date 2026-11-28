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
  void aStoredCidrIsWrittenAsASaveWouldWriteIt() {
    assertThat(Cidr.key("10.1.2.3/24")).isEqualTo("10.1.2.0/24");
    assertThat(Cidr.key("fd00:0:0:0:0:0:0:0/8")).isEqualTo("fd00::/8");
    // Free text an older validator let through is only trimmed.
    assertThat(Cidr.key(" gw.corp/24 ")).isEqualTo("gw.corp/24");
  }

  @Test
  void aSpellingSentBackExactlyAsSavedIsKept_anythingNewIsNormalised() {
    java.util.Set<String> saved = java.util.Set.of("10.62.0.9/24", "10.0.0.01/24");
    // A row V86 left in its old spelling: still the same entry when the list sends it back.
    assertThat(Cidr.asSaved(" 10.62.0.9/24 ", saved, Cidr::normalise)).isEqualTo("10.62.0.9/24");
    assertThat(Cidr.asSaved("10.0.0.01/24", saved, Cidr::normalise)).isEqualTo("10.0.0.01/24");
    assertThat(Cidr.asSaved("10.63.0.9/24", saved, Cidr::normalise)).isEqualTo("10.63.0.0/24");
    assertThatThrownBy(() -> Cidr.asSaved("10.0.0.02/24", saved, Cidr::normalise))
        .hasMessageStartingWith("Invalid CIDR");
  }

  @Test
  void readsAddressLiteralsOnly_neverADnsLookup() {
    assertThat(Cidr.addressBytes("10.0.0.01")).containsExactly(10, 0, 0, 1); // an old row still reads
    assertThat(Cidr.addressBytes("fe80::1%eth0")).hasSize(16); // the scope id is dropped
    assertThat(Cidr.addressBytes(" FD00::1 ")).hasSize(16);
    assertThat(Cidr.addressBytes("gw.corp")).isNull();
    assertThat(Cidr.addressBytes("dead.beef")).isNull(); // hex letters, but a name to InetAddress
    assertThat(Cidr.addressBytes("10.1")).isNull(); // InetAddress reads this as 10.0.0.1
    assertThat(Cidr.addressBytes("10.0.0.256")).isNull();
    assertThat(Cidr.addressBytes("aa:bb:cc:dd:ee:ff:00")).isNull(); // not an address
    assertThat(Cidr.addressBytes("1::2::3")).isNull();
    assertThat(Cidr.addressBytes(" ")).isNull();
    assertThat(Cidr.addressBytes(null)).isNull();
  }

  @Test
  void writesAnAddressAsItIsTyped() {
    assertThat(Cidr.formatAddress(Cidr.addressBytes("2001:0db8:0000:0000:0000:0000:0000:0001")))
        .isEqualTo("2001:db8::1");
    assertThat(Cidr.formatAddress(Cidr.addressBytes("10.0.0.01"))).isEqualTo("10.0.0.1");
    byte[] mapped = new byte[16];
    mapped[10] = (byte) 0xff;
    mapped[11] = (byte) 0xff;
    mapped[12] = 10;
    mapped[15] = 1;
    assertThat(Cidr.formatAddress(mapped)).isEqualTo("::ffff:10.0.0.1"); // RFC 5952 §5
  }
}
