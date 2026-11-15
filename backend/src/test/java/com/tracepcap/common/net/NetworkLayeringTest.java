package com.tracepcap.common.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class NetworkLayeringTest {

  record E(String cidr, String value, boolean hidden) {}

  private static List<E> effective(List<E> defaults, List<E> network) {
    return NetworkLayering.effective(defaults, network, E::cidr, E::hidden);
  }

  @Test
  void noNetworkEntriesIsTheDefault() {
    var defaults = List.of(new E("10.0.0.0/8", "corp", false));
    assertThat(effective(defaults, List.of())).isEqualTo(defaults);
    assertThat(effective(defaults, null)).isEqualTo(defaults);
  }

  @Test
  void overridesAddsAndHidesPerCidr_networkFirst() {
    var defaults =
        List.of(
            new E("10.0.0.0/8", "corp", false),
            new E("192.168.0.0/16", "lab", false),
            new E("172.16.0.0/12", "vpn", false));
    var network =
        List.of(
            new E("10.0.0.0/8", "hq", false), // override
            new E("100.64.0.0/10", "cgnat", false), // add
            new E("172.16.0.0/12", "vpn", true)); // hide
    assertThat(effective(defaults, network))
        .extracting(E::value)
        .containsExactly("hq", "cgnat", "lab");
  }
}
