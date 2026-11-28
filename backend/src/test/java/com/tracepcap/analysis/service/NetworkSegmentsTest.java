package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.entity.DhcpLeaseEntity;
import com.tracepcap.analysis.entity.RouterAdvertEntity;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Telling the networks in a capture apart from their DHCP leases (#462). */
class NetworkSegmentsTest {

  private static DhcpLeaseEntity ack(String ip, String mac, String serverMac, String domain, Integer vlan) {
    return DhcpLeaseEntity.builder()
        .ip(ip).mac(mac).serverMac(serverMac).serverId("192.168.1.1").router("192.168.1.1")
        .domain(domain).subnetMask("255.255.255.0").vlanId(vlan).leaseSeconds(3600L).build();
  }

  @Test
  void twoRoutersOnOneRange_areTwoNetworks_andTheSharedAddressesAreListed() {
    var r = NetworkSegments.of(List.of(
        ack("192.168.1.10", "aa:00:00:00:00:10", "00:1b:21:aa:00:01", "hq.corp.example", null),
        ack("192.168.1.11", "aa:00:00:00:00:11", "00:1b:21:aa:00:01", "hq.corp.example", null),
        ack("192.168.1.10", "bb:00:00:00:00:10", "00:1b:21:bb:00:01", "branch.corp.example", null)));
    assertThat(r.segments()).extracting(NetworkSegments.Segment::label)
        .containsExactly("hq.corp.example", "branch.corp.example");
    assertThat(r.overlaps()).hasSize(1);
    assertThat(r.overlaps().get(0).cidr()).isEqualTo("192.168.1.0/24");
    // .10 is leased on both, and both routers are .1.
    assertThat(r.overlaps().get(0).sharedAddresses()).containsExactly("192.168.1.1", "192.168.1.10");
    assertThat(r.addressesOnSeveralNetworks().get("192.168.1.10"))
        .containsExactly("hq.corp.example", "branch.corp.example");
    assertThat(r.addressesOnSeveralNetworks()).doesNotContainKey("192.168.1.11");
  }

  @Test
  void aVlanTag_separatesNetworks_evenBehindOneServerMac() {
    var r = NetworkSegments.of(List.of(
        ack("10.0.0.5", "aa:00:00:00:00:05", "00:1b:21:cc:00:01", null, 10),
        ack("10.0.0.5", "bb:00:00:00:00:05", "00:1b:21:cc:00:01", null, 20)));
    assertThat(r.segments()).extracting(NetworkSegments.Segment::label).containsExactly("VLAN 10", "VLAN 20");
    assertThat(r.overlaps().get(0).sharedAddresses()).contains("10.0.0.5");
  }

  @Test
  void separateRanges_areNotAnOverlap() {
    var r = NetworkSegments.of(List.of(
        ack("192.168.1.10", "aa:00:00:00:00:10", "00:1b:21:aa:00:01", "hq", null),
        ack("192.168.2.10", "bb:00:00:00:00:10", "00:1b:21:bb:00:01", "branch", null)));
    assertThat(r.segments()).hasSize(2);
    assertThat(r.overlaps()).isEmpty();
  }

  @Test
  void aRequestWithoutAnAck_joinsTheNetworkItsClientWasAckedOn_andNoAckMeansNoNetwork() {
    var request = DhcpLeaseEntity.builder().ip("192.168.1.10").mac("aa:00:00:00:00:10").hostname("HQ-LAPTOP").build();
    var r = NetworkSegments.of(List.of(
        ack("192.168.1.10", "aa:00:00:00:00:10", "00:1b:21:aa:00:01", "hq", null), request,
        DhcpLeaseEntity.builder().ip("192.168.1.99").mac("cc:00:00:00:00:99").build()));
    assertThat(r.segments()).hasSize(1);
    assertThat(r.segments().get(0).clients()).singleElement()
        .satisfies(c -> assertThat(c.hostname()).isEqualTo("HQ-LAPTOP"));
  }

  @Test
  void cidrComesFromTheMask_orFallsBackToSlash24() {
    var c = List.of(new NetworkSegments.Client("10.1.2.3", "m", null));
    assertThat(NetworkSegments.cidr(c, "255.255.0.0")).isEqualTo("10.1.0.0/16");
    assertThat(NetworkSegments.cidr(c, null)).isEqualTo("10.1.2.0/24");
    assertThat(NetworkSegments.intersects("10.1.0.0/16", "10.1.2.0/24")).isTrue();
    assertThat(NetworkSegments.intersects("10.1.0.0/16", "10.2.0.0/16")).isFalse();
  }

  private static RouterAdvertEntity ra(String mac, String ip, Integer vlan, String... prefixes) {
    return RouterAdvertEntity.builder().routerMac(mac).routerIp(ip).vlanId(vlan).prefixes(prefixes).build();
  }

  @Test
  void twoSitesAdvertisingOnePrefix_overlapOnIt() {
    // Two sites that both picked fd00:1::/64 (a ULA collision): one range, two networks.
    var r = NetworkSegments.of(
        List.of(DhcpLeaseEntity.builder().ip("fd00:1::5").mac("aa:00:00:00:00:05").serverMac("00:1b:21:aa:00:01").build(),
            DhcpLeaseEntity.builder().ip("fd00:1::5").mac("bb:00:00:00:00:05").serverMac("00:1b:21:bb:00:01").build()),
        List.of(ra("00:1b:21:aa:00:01", "fe80::a", null, "fd00:1::/64"), ra("00:1b:21:bb:00:01", "fe80::b", null, "fd00:1::/64")));
    assertThat(r.segments()).extracting(NetworkSegments.Segment::key)
        .containsExactly("server:00:1b:21:aa:00:01", "server:00:1b:21:bb:00:01");
    assertThat(r.overlaps()).singleElement().satisfies(o -> {
      assertThat(o.cidr()).isEqualTo("fd00:1::/64");
      assertThat(o.sharedAddresses()).containsExactly("fd00:1::5");
    });
  }

  @Test
  void distinctPrefixesAndLinkLocals_areNotAnOverlap() {
    var r = NetworkSegments.of(List.of(),
        List.of(ra("00:1b:21:aa:00:01", "fe80::a", 10, "fd00:a::/64"), ra("00:1b:21:bb:00:01", "fe80::b", 20, "fd00:b::/64")));
    assertThat(r.segments()).hasSize(2);
    assertThat(r.overlaps()).isEmpty();
  }

  @Test
  void anIpv4OverlapStillNamesTheIpv4Range_whenTheirRoutersAlsoShareALinkLocal() {
    var r = NetworkSegments.of(
        List.of(ack("10.0.0.5", "aa:00:00:00:00:05", "00:1b:21:cc:00:01", null, 10),
            ack("10.0.0.5", "bb:00:00:00:00:05", "00:1b:21:cc:00:01", null, 20)),
        List.of(ra("00:1b:21:cc:00:01", "fe80::1", 10, "fd00:a::/64"), ra("00:1b:21:cc:00:02", "fe80::1", 20, "fd00:b::/64")));
    assertThat(r.overlaps()).singleElement().satisfies(o -> {
      assertThat(o.cidr()).isEqualTo("10.0.0.0/24");
      assertThat(o.sharedAddresses()).containsExactly("10.0.0.5", "192.168.1.1", "fe80::1");
    });
  }

  @Test
  void ipv6RangesIntersect() {
    assertThat(NetworkSegments.intersects("fd00::/48", "fd00:0:0:1::/64")).isTrue();
    assertThat(NetworkSegments.intersects("fd00:1::/64", "fd00:2::/64")).isFalse();
    assertThat(NetworkSegments.intersects("10.0.0.0/8", "fd00::/8")).isFalse();
  }

  @Test
  void oneRouterOnSeveralVlans_withOneLinkLocal_isOneMachine() {
    // Router-on-a-stick: one MAC, one EUI-64 link-local on every VLAN.
    var r = NetworkSegments.of(List.of(),
        List.of(ra("00:1b:21:cc:00:01", "fe80::21b:21ff:fecc:1", 10, "fd00:a::/64"),
            ra("00:1b:21:cc:00:01", "fe80::21b:21ff:fecc:1", 20, "fd00:b::/64")));
    assertThat(r.overlaps()).isEmpty();
    assertThat(r.devicesOnSeveralNetworks()).isEmpty();
  }

  @Test
  void anUntaggedRouterThatIsntTheDhcpServer_joinsItsLinksIpv4Network() {
    // A Windows DHCP server leases IPv4; the router advertises IPv6. No VLAN: one link.
    var r = NetworkSegments.of(
        List.of(ack("10.0.0.10", "aa:00:00:00:00:10", "00:15:5d:00:00:01", "corp", null)),
        List.of(ra("00:1b:21:aa:00:01", "fe80::1", null, "fd00::/64")));
    assertThat(r.segments()).singleElement().satisfies(s -> {
      assertThat(s.key()).isEqualTo("server:00:15:5d:00:00:01");
      assertThat(s.ranges()).containsExactly("10.0.0.0/24", "fd00::/64");
      assertThat(s.routerMacs()).containsEntry("fe80::1", "00:1b:21:aa:00:01");
    });
  }

  @Test
  void anApipaAddressIsNotAnIpv6LinkLocalOverlap() {
    var r = NetworkSegments.of(List.of(
        DhcpLeaseEntity.builder().ip("10.1.0.5").mac("aa:00:00:00:00:05").serverMac("00:1b:21:aa:00:01").router("169.254.1.1").subnetMask("255.255.255.0").build(),
        DhcpLeaseEntity.builder().ip("10.2.0.5").mac("bb:00:00:00:00:05").serverMac("00:1b:21:bb:00:01").router("169.254.1.1").subnetMask("255.255.255.0").build()));
    assertThat(r.overlaps()).isEmpty();
  }
}
