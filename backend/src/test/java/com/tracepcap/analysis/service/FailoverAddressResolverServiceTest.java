package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import org.junit.jupiter.api.Test;

/**
 * Runs the real tshark pass on identity-cases.pcap (#918 item 2). The resolver swallows tshark
 * failures by design, so without this an invalid display filter would just find nothing.
 */
class FailoverAddressResolverServiceTest {

  @Test
  void findsTheVrrpVirtualAddressAndItsRouters() throws Exception {
    assumeTrue(new ProcessBuilder("tshark", "-v").start().waitFor() == 0, "tshark not installed");
    File pcap = new File("src/test/resources/fixtures/identity-cases.pcap");
    var found = new FailoverAddressResolverService().resolve(pcap);
    assertThat(found).containsKey("10.0.0.254");
    assertThat(found.get("10.0.0.254").protocol()).isEqualTo("VRRP");
    assertThat(found.get("10.0.0.254").members()).containsExactly("10.0.0.2", "10.0.0.3");
  }
}
