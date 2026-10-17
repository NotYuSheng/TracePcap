package com.tracepcap.story.service.detector;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.Findings;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.analysis.spi.ConversationLookup.TlsFacts;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The beacon detector's job is "a host beaconing out on a schedule" — not "any regular traffic".
 * The first test replays the failure that motivated #823 (a workstation's NetBIOS keepalive to its
 * domain controller) with the data shape the parser really produces.
 */
class BeaconDetectorTest {

  private static final UUID FILE = UUID.randomUUID();
  private static final LocalDateTime T0 = LocalDateTime.of(2024, 7, 30, 10, 41, 10);
  private static final TlsFacts NO_TLS = new TlsFacts(null, null, null, null, null, null, null);

  private final BeaconDetector detector = new BeaconDetector();

  private ScanContext context(List<ConversationFacts> convs) {
    return new ScanContext() {
      public UUID fileId() { return FILE; }
      public long totalConversations() { return convs.size(); }
      public long totalBytes() { return 0; }
      public List<ConversationFacts> conversations() { return convs; }
      public List<ConversationFacts> tlsConversations() { return List.of(); }
    };
  }

  private static ConversationFacts flow(
      String src, int srcPort, String dst, int dstPort, String initiator, String proto,
      String app, LocalDateTime start) {
    return new ConversationFacts(
        UUID.randomUUID(), FILE,
        new FlowIdentity(src, srcPort, dst, dstPort, initiator, initiator == null ? null : srcPort,
            proto, 8, 900, start, start.plusNanos(20_000_000L)),
        NO_TLS,
        new Findings(app, null, null, List.of(), List.of(), List.of(), List.of()));
  }

  /** {@code events} flows spaced {@code everySec} apart, one row per protocol view, each a few ms apart. */
  private static List<ConversationFacts> periodic(
      String client, String server, int serverPort, String initiator, String app,
      int events, long everySec, String... protocolViews) {
    List<ConversationFacts> out = new ArrayList<>();
    for (int i = 0; i < events; i++) {
      for (int v = 0; v < protocolViews.length; v++) {
        out.add(flow(client, 50000 + i, server, serverPort, initiator, protocolViews[v], app,
            T0.plusSeconds(i * everySec).plusNanos(v * 1_500_000L)));
      }
    }
    return out;
  }

  @Test
  void aWorkstationsNetbiosKeepaliveToItsDomainController_isNotABeacon() {
    // 5 events, exactly 30 s apart, seen as four protocol views (TCP/NBSS/SMB/LANMAN), nDPI: NetBIOS.
    List<ConversationFacts> convs = periodic(
        "172.16.1.66", "172.16.1.4", 139, "172.16.1.66", "NetBIOS", 5, 30, "TCP", "NBSS", "SMB", "LANMAN");

    assertThat(detector.scan(context(convs))).isEmpty();
  }

  @Test
  void internalRegularityOnAServicePort_isSkippedEvenWhenNdpiCouldNotNameIt() {
    List<ConversationFacts> convs = periodic(
        "172.16.1.66", "172.16.1.4", 445, "172.16.1.66", "", 5, 30, "TCP");

    assertThat(detector.scan(context(convs))).isEmpty();
  }

  @Test
  void internalRegularityToAnUnexplainedPort_isReportedNeutrally_notAsC2() {
    List<ConversationFacts> convs = periodic(
        "172.16.1.66", "172.16.1.50", 7777, "172.16.1.66", "", 5, 30, "TCP");

    List<Finding> findings = detector.scan(context(convs));

    assertThat(findings).singleElement().satisfies(f -> {
      assertThat(f.getSeverity()).isEqualTo(Severity.MEDIUM); // not CRITICAL
      assertThat(f.getSummary()).contains("internal host").contains("not, by itself, an indicator");
      assertThat(f.getSummary()).doesNotContain("consistent with C2 keepalive");
      assertThat(f.getMetrics()).containsEntry("direction", "internal");
    });
  }

  @Test
  void periodicTrafficToAnExternalHost_isStillACriticalBeacon() {
    List<ConversationFacts> convs = periodic(
        "172.16.1.66", "141.98.10.79", 12132, "172.16.1.66", "", 5, 30, "TCP");

    assertThat(detector.scan(context(convs))).singleElement().satisfies(f -> {
      assertThat(f.getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(f.getSummary()).contains("consistent with C2 keepalive");
      assertThat(f.getMetrics()).containsEntry("direction", "outbound");
    });
  }

  @Test
  void oneSessionSeenAsSeveralProtocolViews_isOneFinding_notOnePerView() {
    // The parser stores a TCP session as several rows at the same instant. That used to yield one
    // finding per view, filling the result cap with copies of a single beacon.
    List<ConversationFacts> convs = periodic(
        "172.16.1.66", "141.98.10.79", 12132, "172.16.1.66", "", 5, 30, "TCP", "NBSS", "SMB", "LANMAN");

    List<Finding> findings = detector.scan(context(convs));

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).getMetrics().get("protocolViews").toString())
        .contains("TCP").contains("NBSS").contains("SMB").contains("LANMAN");
  }

  @Test
  void exactIntervalInternalTraffic_cannotCrowdARealBeaconOutOfTheCappedResult() {
    // Six internal pairs with CV 0.000 would take every one of the 5 slots if ordering were by CV
    // alone. The external beacon here has jitter, so it sorts later by CV — it must still appear.
    List<ConversationFacts> convs = new ArrayList<>();
    for (int i = 0; i < 6; i++) {
      convs.addAll(periodic("172.16.1.66", "172.16.1." + (100 + i), 7777, "172.16.1.66", "", 5, 30, "TCP"));
    }
    long[] jittered = {0, 28, 61, 88, 121, 149}; // seconds: irregular, CV ~ 0.1–0.2
    for (int i = 0; i < jittered.length; i++) {
      convs.add(flow("172.16.1.66", 50100 + i, "141.98.10.79", 12132, "172.16.1.66", "TCP", "",
          T0.plusSeconds(jittered[i])));
    }

    List<Finding> findings = detector.scan(context(convs));

    assertThat(findings).hasSize(5);
    assertThat(findings.get(0).getMetrics()).containsEntry("direction", "outbound");
  }

  @Test
  void theServerIsFoundFromTheInitiator_notFromWhicheverAddressWasStoredFirst() {
    // Stored with the external address as "src" (keys are normalised), but the internal host
    // initiated: the server port is 12132 (src port here), and the client's ephemeral port varies.
    // Read naively ("dstPort is the server"), every flow would have a different key and none would
    // group into a beacon.
    List<ConversationFacts> convs = new ArrayList<>();
    for (int i = 0; i < 5; i++) {
      convs.add(flow("141.98.10.79", 12132, "172.16.1.66", 49000 + i, "172.16.1.66", "TCP", "",
          T0.plusSeconds(i * 30L)));
    }

    assertThat(detector.scan(context(convs))).singleElement().satisfies(f -> {
      assertThat(f.getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(f.getMetrics()).containsEntry("dstPort", "12132");
      assertThat(f.getAffectedIps()).containsExactly("172.16.1.66", "141.98.10.79");
    });
  }

  @Test
  void inboundPeriodicTraffic_isNotAHostBeaconingOut() {
    // The external host initiated: this is someone connecting in, not the host beaconing out.
    List<ConversationFacts> convs = periodic(
        "141.98.10.79", "172.16.1.66", 8000, "141.98.10.79", "", 5, 30, "TCP");

    assertThat(detector.scan(context(convs))).isEmpty();
  }

  @Test
  void withNoKnownInitiator_theInternalHostIsTakenAsTheClient() {
    // UDP has no handshake, so the initiator is unknown. One endpoint is internal: it is the one
    // that would be beaconing out, whichever address happened to be stored first.
    List<ConversationFacts> convs = new ArrayList<>();
    for (int i = 0; i < 5; i++) {
      convs.add(flow("141.98.10.79", 5353 + 4000, "172.16.1.66", 40000, null, "UDP", "", T0.plusSeconds(i * 30L)));
    }

    assertThat(detector.scan(context(convs))).singleElement()
        .satisfies(f -> assertThat(f.getMetrics()).containsEntry("direction", "outbound"));
  }

  @Test
  void irregularTraffic_andTooFewFlows_areNotBeacons() {
    List<ConversationFacts> two = periodic("172.16.1.66", "141.98.10.79", 12132, "172.16.1.66", "", 2, 30, "TCP");
    assertThat(detector.scan(context(two))).isEmpty();

    List<ConversationFacts> irregular = new ArrayList<>();
    long[] secs = {0, 3, 50, 52, 190, 200};
    for (int i = 0; i < secs.length; i++) {
      irregular.add(flow("172.16.1.66", 50000 + i, "141.98.10.79", 12132, "172.16.1.66", "TCP", "",
          T0.plusSeconds(secs[i])));
    }
    assertThat(detector.scan(context(irregular))).isEmpty();
  }
}
