package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CidrBlockTest {

  private static CidrBlock block(String cidr) {
    return CidrBlock.parse(cidr).orElseThrow();
  }

  @Test
  void ipv4() {
    CidrBlock b = block("10.1.0.0/16");
    assertThat(b.contains("10.1.255.7")).isTrue();
    assertThat(b.contains("10.2.0.1")).isFalse();
    assertThat(block("0.0.0.0/0").contains("8.8.8.8")).isTrue();
    assertThat(block("10.1.2.0/23").contains("10.1.3.200")).isTrue();
    assertThat(block("10.1.2.0/23").contains("10.1.4.1")).isFalse();
  }

  @Test
  void ipv6_compressedOrNot() {
    CidrBlock b = block("fd00:0:0:1::/64");
    assertThat(b.contains("fd00::1:0:0:0:9")).isTrue();
    assertThat(b.contains("FD00:0000:0000:0001:abcd::1")).isTrue();
    assertThat(b.contains("fd00:0:0:2::1")).isFalse();
    assertThat(block("fe80::/10").contains("febf::1%eth0")).isTrue();
    assertThat(block("fe80::/10").contains("fec0::1")).isFalse();
    assertThat(block("::/0").contains("2001:db8::1")).isTrue();
  }

  @Test
  void anotherFamilyIsNeverInside() {
    assertThat(block("0.0.0.0/0").contains("::1")).isFalse();
    assertThat(block("::/0").contains("10.0.0.1")).isFalse();
  }

  @Test
  void readsRowsAsSaved() {
    assertThat(block("10.1.2.3/24")).hasToString("10.1.2.0/24"); // host bits dropped
    assertThat(block("10.0.0.5")).hasToString("10.0.0.5/32"); // a bare address is one host
    assertThat(block(" 10.0.0.01/24 ").contains("10.0.0.9")).isTrue(); // an older spelling
    assertThat(block("FD00:0:0:0:0:0:0:0/8")).hasToString("fd00::/8");
    assertThat(block("10.1.2.3/24")).isEqualTo(block("10.1.2.0/24"));
  }

  @Test
  void anythingElseIsNoBlock_andContainsNothing() {
    for (String bad : new String[] {"gw.corp/24", "10.0.0.0/33", "fd00::/129", "10.0.0.0/x", "", null}) {
      assertThat(CidrBlock.parse(bad)).as(String.valueOf(bad)).isEmpty();
    }
    CidrBlock b = block("10.0.0.0/8");
    assertThat(b.contains("aa:bb:cc:dd:ee:ff")).isFalse();
    assertThat(b.contains("host.example")).isFalse();
    assertThat(b.contains((String) null)).isFalse();
  }

  @Test
  void theOneWayToAsk() {
    assertThat(CidrBlock.contains("fd00::/8", "fd12::1")).isTrue();
    assertThat(CidrBlock.contains("10.0.0.0/8", "10.9.9.9")).isTrue();
    assertThat(CidrBlock.contains("gw.corp/24", "10.0.0.1")).isFalse(); // never resolved
    assertThat(CidrBlock.contains(null, "10.0.0.1")).isFalse();
    assertThat(CidrBlock.contains("10.0.0.0/8", (String) null)).isFalse();
  }

  @Test
  void anIpv4MappedNetworkReadsAsIpv4_asItsAddressesDo() {
    assertThat(block("::ffff:0:0/96")).hasToString("0.0.0.0/0");
    assertThat(block("::ffff:10.0.0.0/120")).hasToString("10.0.0.0/24");
    assertThat(block("::ffff:10.0.0.0/120").contains("::ffff:10.0.0.7")).isTrue();
    assertThat(CidrBlock.parse("::ffff:10.0.0.0/64")).isEmpty(); // wider than the mapped range
  }
}
