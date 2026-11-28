package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TsharkAddressFieldsTest {

  private static final String[] FIELDS = {"frame.number", "ip.src", "ip.dst", "dns.qry.name"};

  @Test
  void asksForTheIpv6TwinsLast() {
    assertThat(TsharkAddressFields.withIpv6(FIELDS))
        .containsExactly("frame.number", "ip.src", "ip.dst", "dns.qry.name", "ipv6.src", "ipv6.dst");
    assertThat(TsharkAddressFields.command(new String[] {"ip.src"}, "tshark", "-r", "x"))
        .containsExactly("tshark", "-r", "x", "-e", "ip.src", "-e", "ipv6.src");
  }

  @Test
  void foldsAnIpv6PacketIntoTheIpv4Layout() {
    String[] row = {"7", "", "", "a.example", "fd00::1", "fd00::2"};
    assertThat(TsharkAddressFields.fold(row, FIELDS)).containsExactly("7", "fd00::1", "fd00::2", "a.example");
  }

  @Test
  void anIpv4PacketKeepsItsAddresses() {
    String[] row = {"7", "10.0.0.1", "10.0.0.2", "a.example", "", ""};
    assertThat(TsharkAddressFields.fold(row, FIELDS)).containsExactly("7", "10.0.0.1", "10.0.0.2", "a.example");
  }

  @Test
  void aValueContainingTheSeparatorStaysWhole() {
    // A DNS name with '|' splits into more cells; the twins are still the last two.
    String[] row = {"7", "", "", "a|b", "c.example", "fd00::1", "fd00::2"};
    assertThat(TsharkAddressFields.fold(row, FIELDS))
        .containsExactly("7", "fd00::1", "fd00::2", "a|b", "c.example");
  }

  @Test
  void aShortRowIsLeftAlone() {
    String[] row = {"7", "10.0.0.1"};
    assertThat(TsharkAddressFields.fold(row, FIELDS)).isSameAs(row);
  }
}
