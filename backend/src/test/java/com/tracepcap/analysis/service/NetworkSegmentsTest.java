package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.entity.DhcpLeaseEntity;
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
}
