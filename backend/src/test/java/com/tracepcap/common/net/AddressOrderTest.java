package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Addresses sort by value: IPv4, then IPv6, then anything else (#1357). */
class AddressOrderTest {

  @Test
  void sortsBothFamiliesByValue() {
    List<String> ips = new ArrayList<>(List.of("fd00::10", "10.0.0.10", "aa:bb:cc:dd:ee:ff", "fd00::9", "10.0.0.9", "2001:db8::1"));
    ips.sort(Cidr.ADDRESS_ORDER);
    assertThat(ips).containsExactly("10.0.0.9", "10.0.0.10", "2001:db8::1", "fd00::9", "fd00::10", "aa:bb:cc:dd:ee:ff");
  }
}
