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
}
