package com.tracepcap.hostclassification.service.classifier.signals;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.HostProfile;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The SERVER vote must follow the MEASURED connection initiator (#496), not the sorted conversation
 * endpoints — a host is a server because it answers connections it never opens, not because it holds
 * a low port.
 */
class TrafficPatternSignalTest {

  private final TrafficPatternSignal signal = new TrafficPatternSignal();

  private HostContext ctx(HostProfile p) {
    return new HostContext("10.0.0.1", p, null, null, null, null, null, Set.of());
  }

  @Test
  void answersButNeverInitiates_onWellKnownPort_votesServer() {
    HostProfile p = new HostProfile();
    p.conversationCount = 3;
    p.totalPackets = 1000; // avoid the low-volume IoT vote
    p.measuredResponses = 3;
    p.measuredInitiations = 0;
    p.respondedOnPorts.add(443);

    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(p), board);

    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.SERVER);
  }

  @Test
  void directionUnknownFlowsOnly_doNotVoteServer() {
    // UDP/ICMP/ARP or a mid-flow capture: no measured initiator, so nothing directional is recorded.
    HostProfile p = new HostProfile();
    p.conversationCount = 4;
    p.totalPackets = 1000;
    p.measuredResponses = 0;
    p.measuredInitiations = 0;

    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(p), board);

    assertThat(board.scores()).doesNotContainKey(DeviceTypes.SERVER);
  }

  @Test
  void mostlyOpensConnections_withVariedApps_votesClient() {
    HostProfile p = new HostProfile();
    p.conversationCount = 8;
    p.totalPackets = 5000;
    p.measuredInitiations = 8;
    p.measuredResponses = 0;
    p.apps.addAll(Set.of("Netflix", "WhatsApp", "Spotify", "Chrome"));

    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(p), board);

    assertThat(board.scores()).doesNotContainKey(DeviceTypes.SERVER);
    assertThat(board.scores())
        .containsKeys(DeviceTypes.MOBILE, DeviceTypes.LAPTOP_DESKTOP);
  }
}
