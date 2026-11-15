package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DhcpLeaseResolverServiceTest {

  @Test
  void parsesAcksAndRequests_skipsEmptyAddresses_keepsTheWindow() {
    Map<String, DhcpLeaseResolverService.Lease> leases = new LinkedHashMap<>();
    // ACK: yiaddr to chaddr.
    DhcpLeaseResolverService.parseRow("1730000000.0|5|10.0.0.50|0.0.0.0||BB:BB:BB:00:00:01|".split("\\|", -1), leases);
    // REQUEST for the same address, later, naming itself.
    DhcpLeaseResolverService.parseRow(
        "1730000060.0|3|0.0.0.0|0.0.0.0|10.0.0.50|bb:bb:bb:00:00:01|LAPTOP-ALICE".split("\\|", -1), leases);
    // A DISCOVER-like row with no address at all: ignored.
    DhcpLeaseResolverService.parseRow("1730000070.0|3|0.0.0.0|0.0.0.0||cc:cc:cc:00:00:02|x".split("\\|", -1), leases);
    assertThat(leases).hasSize(1);
    var l = leases.values().iterator().next();
    assertThat(l.mac()).isEqualTo("bb:bb:bb:00:00:01");
    assertThat(l.hostname()).isEqualTo("LAPTOP-ALICE");
    assertThat(l.lastSeen()).isAfter(l.firstSeen());
  }

  /** The real tshark pass, so an invalid field or filter can't silently find nothing. */
  @Test
  void findsTheLaptopAndPhoneLeasesInTheFixture() throws Exception {
    assumeTrue(new ProcessBuilder("tshark", "-v").start().waitFor() == 0, "tshark not installed");
    var found = new DhcpLeaseResolverService().resolve(new File("src/test/resources/fixtures/identity-cases.pcap"));
    assertThat(found)
        .filteredOn(l -> l.ip().equals("10.0.0.50"))
        .extracting(DhcpLeaseResolverService.Lease::hostname)
        .containsExactlyInAnyOrder("LAPTOP-ALICE", "iPhone-Bob");
  }

  @Test
  void keepsTheDhcpFingerprint_withEveryOccurrenceOn() {
    Map<String, DhcpLeaseResolverService.Lease> leases = new LinkedHashMap<>();
    // occurrence=a: single-valued fields still come once; option 55 comes as a list.
    DhcpLeaseResolverService.parseRow(
        "1730000000.0|3|0.0.0.0|0.0.0.0|10.0.0.61|3a:1f:9c:52:0e:11|Bobs-iPhone|1;121;3;6;15;108;114;119;252|".split("\\|", -1),
        leases);
    var l = leases.values().iterator().next();
    assertThat(l.fingerprint()).isEqualTo("1,121,3,6,15,108,114,119,252");
    assertThat(l.vendorClass()).isNull();
    assertThat(l.hostname()).isEqualTo("Bobs-iPhone");
  }

  /** The real tshark pass reads option 55 from the private-MAC fixture. */
  @Test
  void readsTheFingerprintFromACapture() throws Exception {
    assumeTrue(new ProcessBuilder("tshark", "-v").start().waitFor() == 0, "tshark not installed");
    var found = new DhcpLeaseResolverService().resolve(new File("src/test/resources/fixtures/private_mac_week1.pcap"));
    assertThat(found)
        .filteredOn(l -> "Bobs-iPhone".equals(l.hostname()))
        .extracting(DhcpLeaseResolverService.Lease::fingerprint)
        .containsExactly("1,121,3,6,15,108,114,119,252");
  }

  /** The network each ACK names (#462): the real tshark pass over two sites on one range. */
  @Test
  void readsWhichNetworkEachLeaseCameFrom() throws Exception {
    assumeTrue(new ProcessBuilder("tshark", "-v").start().waitFor() == 0, "tshark not installed");
    var found = new DhcpLeaseResolverService().resolve(new File("src/test/resources/fixtures/two_sites_overlap_untagged.pcap"));
    assertThat(found)
        .filteredOn(l -> l.ip().equals("192.168.1.10") && l.network() != null)
        .extracting(l -> l.network().domain() + "|" + l.network().serverMac() + "|" + l.network().leaseSeconds())
        .containsExactlyInAnyOrder(
            "hq.corp.example|00:1b:21:aa:00:01|86400", "branch.corp.example|00:1b:21:bb:00:01|3600");
  }
}
