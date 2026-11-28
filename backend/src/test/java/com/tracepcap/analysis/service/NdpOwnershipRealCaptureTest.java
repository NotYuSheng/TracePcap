package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * IPv6 Neighbor Discovery says who owns an address, as ARP does for IPv4 (#1357). Real tshark on
 * {@code fixtures/ndp-cases.pcap} (see {@code ndp-cases.gen.py}).
 */
class NdpOwnershipRealCaptureTest {

  private static final File PCAP =
      new File(NdpOwnershipRealCaptureTest.class.getResource("/fixtures/ndp-cases.pcap").getFile());

  private static final PcapParserService.ParseSink SINK =
      new PcapParserService.ParseSink() {
        public UUID conversationStarted(PcapParserService.ConversationStub stub) {
          return UUID.randomUUID();
        }

        public void packetParsed(UUID conversationId, PcapParserService.PacketInfo packet) {}

        public void finish() {}
      };

  private final PcapParserService.PcapAnalysisResult result = parse();

  private static PcapParserService.PcapAnalysisResult parse() {
    PcapParserService parser = new PcapParserService();
    // Spring sets the conversation cap; constructed here, it would be 0.
    org.springframework.test.util.ReflectionTestUtils.setField(parser, "maxConversations", 1000);
    return parser.analyzePcapFile(PCAP, SINK);
  }

  @Test
  void anIpv6HostWithThreeAddressesKeepsItsMac() {
    // Without NDP claims its MAC fronted three unclaimed IPs, read as a router, and no address got it.
    for (String ip : new String[] {"fe80::10", "fd00::10", "fd00::5eed:10"}) {
      assertThat(result.getHostMacs()).as(ip).containsEntry(ip, "aa:aa:aa:00:00:10");
    }
    for (String ip : new String[] {"fd00::10", "fd00::5eed:10"}) {
      assertThat(result.getHostMacObservations().get(ip)).as(ip).containsExactly("aa:aa:aa:00:00:10");
    }
  }

  @Test
  void twoMachinesClaimingOneAddressAreAConflict() {
    assertThat(result.getHostMacObservations().get("fd00::99"))
        .containsExactly("cc:cc:cc:00:00:01", "cc:cc:cc:00:00:02");
    assertThat(result.getArpClaimWindows().get("fd00::99")).containsOnlyKeys("cc:cc:cc:00:00:01", "cc:cc:cc:00:00:02");
  }

  @Test
  void aDuplicateAddressProbeOrAProxyAnswerOwnsNothing() {
    assertThat(result.getHostMacObservations()).doesNotContainKeys("::", "fd00::77", "fd00::88");
  }

  @Test
  void aLinkLocalAddressRepeatsPerLink_soItIsNeverAConflict() {
    // Two VLANs' gateways both advertise from fe80::1, with their own MACs.
    assertThat(result.getHostMacObservations()).doesNotContainKeys("fe80::1", "fe80::10");
    assertThat(result.getArpClaimWindows()).doesNotContainKeys("fe80::1", "fe80::10");
  }

  @Test
  void anIcmpv6ErrorQuotingAnNsClaimsNothingForItsSender() {
    // fd00::1's Parameter Problem quotes the laptop's NS; the quoted option names the laptop's MAC.
    assertThat(result.getHostMacObservations()).doesNotContainKey("fd00::1");
  }
}
