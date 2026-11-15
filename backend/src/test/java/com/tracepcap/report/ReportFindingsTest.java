package com.tracepcap.report;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.dto.occupancy.HostOccupancyResponse;
import com.tracepcap.analysis.dto.segments.NetworkSegmentsResponse;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.Findings;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The report's "Needs a look" (#1152): flags told as sentences, with the right device named. */
class ReportFindingsTest {

  private static final LocalDateTime T0 = LocalDateTime.of(2026, 11, 14, 17, 0);
  private static final LocalDateTime SWAP = T0.plusMinutes(15);

  private static ConversationFacts conv(String src, String dst, int port, String app, LocalDateTime at, String... risks) {
    var flow = new FlowIdentity(src, 40000, dst, port, null, null, "TCP", 8, 4600, at, at.plusSeconds(1));
    var findings = new Findings(app, null, "Web", List.of(risks), List.of(), List.of(), List.of());
    return new ConversationFacts(UUID.randomUUID(), UUID.randomUUID(), flow, null, findings);
  }

  private static HostFacts host(String ip, String mac, String name) {
    return new HostFacts(ip, mac, null, name, name == null ? null : "dhcp", null, null, null, 0, 64,
        "MOBILE", 40, List.of(), List.of(64), "PRIVATE", null, null);
  }

  private static HostOccupancyResponse.Occupancy holder(String mac, String name, LocalDateTime from, LocalDateTime to) {
    return HostOccupancyResponse.Occupancy.builder()
        .mac(mac).hostname(name).startsAt(from).endsAt(to).startSource(from == null ? null : "arp").build();
  }

  private static final List<HostOccupancyResponse.ReusedAddress> SHARED = List.of(
      new HostOccupancyResponse.ReusedAddress("10.20.20.51", List.of(
          holder("8c:71:f8:b0:00:01", "Galaxy-A55", null, SWAP),
          holder("a4:83:e7:b0:00:02", "Visitors-iPhone", SWAP, null))));

  private static final NetworkSegmentsResponse NETWORKS = new NetworkSegmentsResponse(
      List.of(
          new NetworkSegmentsResponse.Segment("vlan:20", "guest.office.example (VLAN 20)", 20, null, List.of(),
              List.of("10.20.20.1"), List.of(), List.of(), "10.20.20.0/24",
              List.of(new NetworkSegmentsResponse.Client("10.20.20.51", "8c:71:f8:b0:00:01", "Galaxy-A55")), List.of()),
          new NetworkSegmentsResponse.Segment("vlan:30", "devices.office.example (VLAN 30)", 30, null, List.of(),
              List.of("10.20.30.1"), List.of(), List.of(), "10.20.30.0/24",
              List.of(new NetworkSegmentsResponse.Client("10.20.30.41", "44:19:b6:c0:00:03", "CAM-ENTRANCE")),
              List.of(new NetworkSegmentsResponse.UnansweredClient("b8:27:eb:5e:00:01", "raspberrypi", 30, 6)))),
      List.of(), List.of());

  private static ReportNames names() {
    return new ReportNames(
        List.of(host("10.20.20.51", "8c:71:f8:b0:00:01", "Galaxy-A55"), host("10.20.30.41", "44:19:b6:c0:00:03", "CAM-ENTRANCE")),
        SHARED, NETWORKS, Map.of("140.82.112.6", "GitHub, Inc."));
  }

  @Test
  void namesTheDeviceThatHeldTheAddressAtTheTime() {
    ReportNames n = names();
    assertThat(n.name("10.20.20.51", T0.plusMinutes(3))).isEqualTo("Galaxy-A55");
    assertThat(n.name("10.20.20.51", T0.plusMinutes(25))).isEqualTo("Visitors-iPhone");
    assertThat(n.name("10.20.20.1", null)).isEqualTo("Gateway");
    assertThat(n.label("140.82.112.6", null)).isEqualTo("140.82.112.6 (GitHub)");
    assertThat(n.networkOf("10.20.30.99")).isEqualTo("devices.office.example (VLAN 30)");
  }

  @Test
  void aRareFlagIsToldPerConversation_aFlagOnMostIsOneLowLine() {
    List<ConversationFacts> flagged = new ArrayList<>();
    flagged.add(conv("10.20.20.51", "10.20.30.41", 23, "Telnet", T0.plusMinutes(25), "unsafe_protocol", "malicious_fingerprint"));
    for (int i = 0; i < 9; i++) flagged.add(conv("10.20.20.51", "140.82.112.6", 443, "TLS", T0.plusMinutes(i), "malicious_fingerprint"));

    var findings = ReportFindings.build(flagged, 20, names(), List.of(), null, true);

    assertThat(findings).hasSize(2);
    var telnet = findings.get(0);
    assertThat(telnet.level()).isEqualTo(ReportFindings.Level.HIGH);
    assertThat(telnet.title()).isEqualTo("Telnet to CAM-ENTRANCE from Visitors-iPhone");
    assertThat(telnet.body())
        .contains("Visitors-iPhone (10.20.20.51, guest.office.example (VLAN 20)) opened Telnet")
        .contains("on port 23 at 17:25:00")
        .contains("without encryption");
    var many = findings.get(1);
    assertThat(many.level()).isEqualTo(ReportFindings.Level.LOW);
    assertThat(many.title()).isEqualTo("Flagged on many conversations: malicious_fingerprint");
    assertThat(many.body()).contains("10 of 20 conversations").contains("TLS 9, Telnet 1").contains("appendix");
  }

  @Test
  void anAddressThatChangedHands_andADeviceNobodyAnswered() {
    var findings = ReportFindings.build(List.of(), 20, names(), SHARED, NETWORKS, false);

    assertThat(findings).extracting(ReportFindings.Finding::title).containsExactly(
        "One address, 2 devices: 10.20.20.51", "A device asked for an address and got none");
    assertThat(findings.get(0).body())
        .isEqualTo("Galaxy-A55 (8c:71:f8:b0:00:01) until 17:15:00, then Visitors-iPhone (a4:83:e7:b0:00:02) from 17:15:00. From ARP.");
    assertThat(findings.get(1).body())
        .isEqualTo("raspberrypi (b8:27:eb:5e:00:01) sent 6 DHCP requests on devices.office.example (VLAN 30). No DHCP server answered.");
  }

  @Test
  void vendorsLoseTheirLegalSuffix() {
    assertThat(ReportService.vendor("Dell Inc.")).isEqualTo("Dell");
    assertThat(ReportService.vendor("Hangzhou Hikvision Digital Technology Co.,Ltd.")).isEqualTo("Hangzhou Hikvision");
    assertThat(ReportService.vendor("Samsung Electronics Co.,Ltd")).isEqualTo("Samsung");
    assertThat(ReportService.device("LAPTOP_DESKTOP", false)).isEqualTo("Laptop/desktop");
    assertThat(ReportService.device("LAPTOP_DESKTOP", true)).isEqualTo("Gateway");
  }

  @Test
  void broadcastMulticastAndUnspecifiedAreNotHosts() {
    assertThat(ReportService.isHost("93.184.216.50")).isTrue();
    assertThat(ReportService.isHost("0.0.0.0")).isFalse();
    assertThat(ReportService.isHost("255.255.255.255")).isFalse();
    assertThat(ReportService.isHost("224.0.0.251")).isFalse();
    assertThat(ReportService.isHost("ff02::fb")).isFalse();
  }

  @Test
  void devicesMergeOnEvidenceNotOnMac() {
    var addrs = new java.util.LinkedHashSet<>(List.of("10.20.10.1", "10.20.20.1", "10.20.30.1", "10.20.10.23", "10.20.10.33", "10.20.10.21"));
    // One DHCP server's three gateways, and a laptop that moved: six addresses, three devices.
    List<String[]> same = List.of(
        new String[] {"10.20.10.1", "10.20.20.1"}, new String[] {"10.20.10.1", "10.20.30.1"},
        new String[] {"10.20.10.23", "10.20.10.33"});
    assertThat(ReportService.deviceCount(addrs, same)).isEqualTo(3);
    assertThat(ReportService.deviceCount(addrs, List.of())).isEqualTo(6);
  }

  @Test
  void longCapturesReadInDays() {
    assertThat(ReportService.duration(27 * 60_000L)).isEqualTo("27 min");
    assertThat(ReportService.duration(26 * 3_600_000L)).isEqualTo("26 h 0 min");
    assertThat(ReportService.duration(10 * 86_400_000L)).isEqualTo("10 days");
  }
}
