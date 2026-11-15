package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Addresses that can be one machine, versus destinations that can't (#918). */
class IpLocalityHostAddressTest {

  @ParameterizedTest
  @ValueSource(strings = {"10.0.0.50", "192.168.1.1", "8.8.8.8", "223.255.255.254", "fe80::1", "2001:db8::5", "::1"})
  void hosts(String ip) {
    assertThat(IpLocality.isHostAddress(ip)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"0.0.0.0", "255.255.255.255", "224.0.0.18", "239.255.255.250", "240.0.0.1", "::", "ff02::1", "FF02::FB", "ff:ff:ff:ff:ff:ff"})
  void notHosts(String ip) {
    assertThat(IpLocality.isHostAddress(ip)).isFalse();
  }
}
