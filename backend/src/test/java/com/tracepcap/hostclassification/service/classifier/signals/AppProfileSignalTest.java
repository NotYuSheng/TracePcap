package com.tracepcap.hostclassification.service.classifier.signals;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.config.DeviceClassificationProperties;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.HostProfile;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Server/IoT app votes must follow the MEASURED serving direction (#539): an endpoint-agnostic
 * protocol name (DNS, SMB, MDNS, …) credits only the side that answered, never the side that
 * queried. Client-leaning app names (mobile/desktop) stay direction-agnostic.
 */
class AppProfileSignalTest {

  private final DeviceClassificationProperties props = props();
  private final AppProfileSignal signal = new AppProfileSignal(props);

  private static DeviceClassificationProperties props() {
    DeviceClassificationProperties p = new DeviceClassificationProperties();
    p.setMobileApps(Set.of("Instagram"));
    p.setDesktopApps(Set.of("Zoom"));
    p.setServerApps(Set.of("DNS", "SMB"));
    p.setWeakServerApps(Set.of("HTTP"));
    p.setIotApps(Set.of("MDNS"));
    p.setIotCategories(Set.of());
    return p;
  }

  private HostContext ctx(HostProfile p) {
    return new HostContext("10.0.0.1", p, null, null, null, null, null, Set.of());
  }

  @Test
  void clientThatOnlyQueriedDns_getsNoServerVote() {
    // Workstation resolving DNS: the app is in `apps` (it spoke it) but not `servedApps` (it never
    // answered). Before #539 this collected a bogus "Server app DNS" vote.
    HostProfile p = new HostProfile();
    p.apps.add("DNS");

    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(p), board);

    assertThat(board.scores()).doesNotContainKey(DeviceTypes.SERVER);
  }

  @Test
  void hostThatAnsweredDns_getsServerVote() {
    HostProfile p = new HostProfile();
    p.apps.add("DNS");
    p.servedApps.add("DNS"); // measured responder on the DNS flow

    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(p), board);

    assertThat(board.scores()).containsKey(DeviceTypes.SERVER);
  }

  @Test
  void mdnsChatterAlone_getsNoIotVote() {
    HostProfile p = new HostProfile();
    p.apps.add("MDNS"); // multicast chatter, no measured responder

    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(p), board);

    assertThat(board.scores()).doesNotContainKey(DeviceTypes.IOT);
  }

  @Test
  void mobileAppVote_isDirectionAgnostic() {
    // Client-leaning apps score whether or not the host served anything.
    HostProfile p = new HostProfile();
    p.apps.add("Instagram");

    ScoreBoard board = new ScoreBoard();
    signal.contribute(ctx(p), board);

    assertThat(board.scores()).containsKey(DeviceTypes.MOBILE);
  }
}
