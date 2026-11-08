package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/** #918 items 1c and 2: every TTL, virtual failover addresses, possibly-two-machines warnings. */
class HostIdentityChecksTest {

  private static HostClassificationEntity host(String ip, String mac) {
    return HostClassificationEntity.builder().ip(ip).mac(mac).deviceType("IOT").confidence(40).winnerScore(20).build();
  }

  @Test
  void anAdvertisedVirtualAddressIsMarked_withItsRouters_andNotClassifiedAsADevice() {
    HostClassificationEntity vip = host("10.0.0.254", "00:00:5e:00:01:0a");
    var adverts =
        Map.of("10.0.0.254", new FailoverAddressResolverService.VirtualAddress("10.0.0.254", "VRRP", new TreeSet<>(Set.of("10.0.0.2", "10.0.0.3"))));
    HostIdentityChecks.apply(List.of(vip), Map.of(), List.of(), adverts);
    assertThat(vip.getAddressKind()).isEqualTo("VIRTUAL_FAILOVER");
    assertThat(vip.getDeviceType()).isEqualTo("VIRTUAL_ADDRESS");
    assertThat(vip.getWinnerReasons()).contains("VRRP").contains("10.0.0.2, 10.0.0.3");
    assertThat(vip.getWinnerScore()).isNull();
  }

  @Test
  void aVirtualRouterMacMarksTheAddressEvenWithoutAdverts() {
    HostClassificationEntity hsrp = host("10.1.0.1", "00:00:0c:07:ac:01");
    HostClassificationEntity carp = host("10.2.0.1", "00:00:5E:00:01:05");
    HostClassificationEntity plain = host("10.3.0.1", "00:11:22:33:44:55");
    HostIdentityChecks.apply(List.of(hsrp, carp, plain), Map.of(), List.of(), Map.of());
    assertThat(hsrp.getAddressKind()).isEqualTo("VIRTUAL_FAILOVER");
    assertThat(hsrp.getWinnerReasons()).contains("HSRP");
    assertThat(carp.getAddressKind()).isEqualTo("VIRTUAL_FAILOVER");
    assertThat(plain.getAddressKind()).isNull();
    assertThat(FailoverAddressResolverService.virtualRouterProtocol("00:00:0c:9f:f1:23")).isEqualTo("HSRP");
  }

  @Test
  void differentTtlFamiliesOrSeveralDhcpNamesWarn_andAllTtlsAreKept() {
    HostClassificationEntity clone = host("10.0.0.70", "ee:ee:ee:00:00:09");
    HostClassificationEntity routed = host("8.8.8.8", null);
    HostClassificationEntity named = host("10.0.0.80", "aa:aa:aa:aa:aa:80");
    var claims =
        List.of(
            new HostnameResolverService.Claim("10.0.0.80", "printer-1", HostnameResolverService.SOURCE_DHCP),
            new HostnameResolverService.Claim("10.0.0.80", "PRINTER-1", HostnameResolverService.SOURCE_DHCP),
            new HostnameResolverService.Claim("10.0.0.80", "other", "mdns"));
    HostIdentityChecks.apply(
        List.of(clone, routed, named),
        Map.of("10.0.0.70", List.of(128, 64, 64), "8.8.8.8", List.of(118, 120)),
        claims,
        Map.of());

    assertThat(clone.getTtls()).containsExactly(64, 128);
    assertThat(clone.getIdentityWarning()).contains("Possibly more than one machine").contains("Windows");
    // Hops lower a TTL within one family: 118 and 120 both started at 128. No warning.
    assertThat(routed.getIdentityWarning()).isNull();
    // The same DHCP name in two cases, plus an mDNS name: one DHCP hostname. No warning.
    assertThat(named.getIdentityWarning()).isNull();
  }

  @Test
  void ttlFamilies() {
    assertThat(HostIdentityChecks.family(64)).isEqualTo(64);
    assertThat(HostIdentityChecks.family(65)).isEqualTo(128);
    assertThat(HostIdentityChecks.family(128)).isEqualTo(128);
    assertThat(HostIdentityChecks.family(200)).isEqualTo(255);
  }
}
