package com.tracepcap.subnets.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.common.net.LocalityRules;
import com.tracepcap.subnets.dto.SubnetDefinitionDto;
import java.util.List;
import org.junit.jupiter.api.Test;

/** IPv6 subnet candidates are the local /64s hosts are on (#1357). */
class Ipv6SubnetCandidatesTest {

  private static HostFacts host(String ip, String mac) {
    return new HostFacts(ip, mac, null, null, null, null, null, null, 0, null, null, 0, List.of());
  }

  private static List<SubnetDefinitionDto> candidates(HostFacts... hosts) {
    return SubnetService.ipv6Candidates(List.of(hosts), LocalityRules.RFC_ONLY, 1, 1);
  }

  @Test
  void aSlash64WithThreeMachinesIsACandidate() {
    var out = candidates(
        host("fd00:0:0:1::10", "aa:00:00:00:00:01"),
        host("fd00:0:0:1::20", "aa:00:00:00:00:02"),
        host("fd00:0:0:1:abcd::7", "aa:00:00:00:00:03"),
        host("fd00:0:0:2::10", "aa:00:00:00:00:04")); // a /64 with one machine: not proposed
    assertThat(out).singleElement().satisfies(c -> {
      assertThat(c.getCidr()).isEqualTo("fd00:0:0:1::/64");
      assertThat(c.getHostCount()).isEqualTo(3);
      assertThat(c.getDensityScore()).isNull(); // density means nothing for a /64
    });
  }

  @Test
  void machinesAreCountedByMac_notByAddress() {
    // One laptop's SLAAC and temporary addresses, plus one other machine: two machines.
    assertThat(candidates(
            host("fd00:0:0:1::10", "aa:00:00:00:00:01"),
            host("fd00:0:0:1:5eed::10", "AA:00:00:00:00:01"),
            host("fd00:0:0:1::99", "aa:00:00:00:00:01"),
            host("fd00:0:0:1::20", "aa:00:00:00:00:02")))
        .isEmpty();
  }

  @Test
  void linkLocalPublicAndIpv4AreNever() {
    assertThat(candidates(
            host("fe80::1", "a1:00:00:00:00:01"), host("fe80::2", "a1:00:00:00:00:02"), host("fe80::3", "a1:00:00:00:00:03"),
            host("2001:db8::1", "b1:00:00:00:00:01"), host("2001:db8::2", "b1:00:00:00:00:02"), host("2001:db8::3", "b1:00:00:00:00:03"),
            host("10.0.0.1", "c1:00:00:00:00:01"), host("10.0.0.2", "c1:00:00:00:00:02"), host("10.0.0.3", "c1:00:00:00:00:03")))
        .isEmpty();
  }
}
