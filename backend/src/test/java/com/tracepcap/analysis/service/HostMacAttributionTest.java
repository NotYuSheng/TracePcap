package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** One MAC per IP without handing every off-subnet host the gateway's MAC (#918). */
class HostMacAttributionTest {

  private static LinkedHashSet<String> macs(String... m) {
    return new LinkedHashSet<>(List.of(m));
  }

  @Test
  void aMacFrontingManyIpsWithoutArp_isARouter_andIsNotGivenToThem() {
    String gw = "aa:aa:aa:00:00:01";
    var eth = Map.of(
        "93.184.216.34", macs(gw),
        "151.101.1.69", macs(gw),
        "140.82.112.3", macs(gw),
        "10.0.0.60", macs("bb:bb:bb:00:00:60"));

    var result = PcapParserService.attributeMacs(eth, Map.of());

    assertThat(result).doesNotContainKeys("93.184.216.34", "151.101.1.69", "140.82.112.3");
    assertThat(result).containsEntry("10.0.0.60", "bb:bb:bb:00:00:60"); // an ordinary local host
  }

  @Test
  void anArpClaimWins_evenForTheRoutersOwnIp() {
    String gw = "aa:aa:aa:00:00:01";
    var eth = Map.of(
        "10.0.0.1", macs(gw),
        "8.8.8.8", macs(gw),
        "1.1.1.1", macs(gw),
        "9.9.9.9", macs(gw));
    var arp = Map.of("10.0.0.1", macs(gw));

    var result = PcapParserService.attributeMacs(eth, arp);

    assertThat(result).containsEntry("10.0.0.1", gw);
    assertThat(result).doesNotContainKeys("8.8.8.8", "1.1.1.1", "9.9.9.9");
  }

  @Test
  void belowTheThreshold_theFirstEthMacIsKept() {
    // Two IPs on one MAC without ARP: a multi-homed host as plausibly as a router, so keep it.
    String m = "cc:cc:cc:00:00:02";
    var result = PcapParserService.attributeMacs(Map.of("10.0.0.5", macs(m), "10.0.0.6", macs(m)), Map.of());

    assertThat(result).containsEntry("10.0.0.5", m).containsEntry("10.0.0.6", m);
  }
}
