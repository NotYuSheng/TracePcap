package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.entity.DhcpLeaseEntity;
import com.tracepcap.analysis.entity.RouterAdvertEntity;
import java.io.File;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * IPv6 networks from router advertisements and DHCPv6 (#1357): real tshark on {@code
 * fixtures/ipv6-segments.pcap} (see {@code ipv6-segments.gen.py}), through the resolver and into
 * {@link NetworkSegments} as the database would hand them back.
 */
class Ipv6SegmentsRealCaptureTest {

  private static final File PCAP =
      new File(Ipv6SegmentsRealCaptureTest.class.getResource("/fixtures/ipv6-segments.pcap").getFile());

  private final DhcpLeaseResolverService.Resolution found = new DhcpLeaseResolverService().resolveAll(PCAP);

  @Test
  void readsEachRoutersAdvertsOnce_andNotAQuotedOne() {
    assertThat(found.adverts())
        .extracting(a -> a.routerMac() + " " + a.routerIp() + " " + a.vlanId() + " " + a.prefixes() + " " + a.domain())
        .containsExactlyInAnyOrder(
            "aa:00:00:00:00:0a fe80::1 10 [fd00:10::/64] hq.example",
            "aa:00:00:00:00:14 fe80::1 20 [fd00:20::/64] null",
            "cc:cc:cc:00:00:01 fe80::30 null [2001:db8:30::/64] null");
  }

  @Test
  void aDhcpv6ReplyIsALease_andARelaysHopIsNot() {
    var v6 = found.leases().stream().filter(l -> l.ip().contains(":")).toList();
    assertThat(v6).singleElement().satisfies(l -> {
      assertThat(l.ip()).isEqualTo("fd00:10::100");
      assertThat(l.mac()).isEqualTo("10:00:00:00:00:01");
      assertThat(l.hostname()).isEqualTo("laptop-a");
      assertThat(l.network().serverMac()).isEqualTo("aa:00:00:00:00:0a");
      assertThat(l.network().domain()).isEqualTo("hq.example");
      assertThat(l.network().leaseSeconds()).isEqualTo(7200L);
      assertThat(l.network().vlanId()).isEqualTo(10);
    });
  }

  @Test
  void aDualStackVlanIsOneNetwork_andLinkLocalRepeatsPerLink() {
    var r = NetworkSegments.of(leases(), adverts());
    assertThat(r.segments())
        .extracting(s -> s.key() + " | " + s.label() + " | " + s.ranges())
        .containsExactly(
            "vlan:10 | hq.example (VLAN 10) | [10.0.10.0/24, fd00:10::/64]",
            "vlan:20 | VLAN 20 | [fd00:20::/64]",
            "server:cc:cc:cc:00:00:01 | Router cc:cc:cc:00:00:01 | [2001:db8:30::/64]");
    // The laptop's IPv4 and IPv6 leases are both its own.
    assertThat(r.segments().get(0).clients()).extracting(NetworkSegments.Client::ip)
        .containsExactly("10.0.10.100", "fd00:10::100");
    // Both VLANs' routers are fe80::1: two machines, one per network, each with its own MAC.
    assertThat(r.overlaps()).singleElement().satisfies(o -> {
      assertThat(o.cidr()).isEqualTo("fe80::/64");
      assertThat(o.segmentKeys()).containsExactly("vlan:10", "vlan:20");
      assertThat(o.sharedAddresses()).containsExactly("fe80::1");
    });
    assertThat(r.devicesOnSeveralNetworks().get("fe80::1"))
        .extracting(d -> d.segmentKey() + " " + d.mac())
        .containsExactly("vlan:10 aa:00:00:00:00:0a", "vlan:20 aa:00:00:00:00:14");
    assertThat(r.macsBySegment().get("vlan:20")).containsExactly("aa:00:00:00:00:14");
  }

  private List<DhcpLeaseEntity> leases() {
    return found.leases().stream()
        .map(l -> {
          var b = DhcpLeaseEntity.builder().ip(l.ip()).mac(l.mac()).hostname(l.hostname())
              .firstSeen(l.firstSeen()).lastSeen(l.lastSeen());
          var n = l.network();
          if (n != null) {
            b.serverMac(n.serverMac()).serverId(n.serverId()).router(n.router()).domain(n.domain())
                .leaseSeconds(n.leaseSeconds()).subnetMask(n.subnetMask()).vlanId(n.vlanId());
          }
          return b.build();
        })
        .toList();
  }

  private List<RouterAdvertEntity> adverts() {
    return found.adverts().stream()
        .map(a -> RouterAdvertEntity.builder().routerMac(a.routerMac()).routerIp(a.routerIp()).vlanId(a.vlanId())
            .prefixes(a.prefixes().toArray(String[]::new)).domain(a.domain())
            .firstSeen(a.firstSeen()).lastSeen(a.lastSeen()).build())
        .toList();
  }
}
