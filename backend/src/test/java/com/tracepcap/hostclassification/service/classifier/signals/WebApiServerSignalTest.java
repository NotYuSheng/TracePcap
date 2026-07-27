package com.tracepcap.hostclassification.service.classifier.signals;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.HostProfile;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import java.util.Set;
import org.junit.jupiter.api.Test;

class WebApiServerSignalTest {

  private final ApiServerSignal apiSignal = new ApiServerSignal();
  private final WebServerSignal webSignal = new WebServerSignal();

  private HostContext ctx(Set<String> roles) {
    return new HostContext("10.0.0.1", new HostProfile(), 64, null, null, null, null, roles);
  }

  @Test
  void apiRole_classifiesApiServer_andOutranksHeuristics() {
    ScoreBoard board = new ScoreBoard();
    board.add(DeviceTypes.SERVER, 60, "inbound-only");
    apiSignal.contribute(ctx(Set.of("api")), board);
    webSignal.contribute(ctx(Set.of("api")), board);

    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.API_SERVER);
  }

  @Test
  void webRole_classifiesWebServer_andOutranksHeuristics() {
    ScoreBoard board = new ScoreBoard();
    board.add(DeviceTypes.ROUTER, 35, "fan-out");
    apiSignal.contribute(ctx(Set.of("web")), board);
    webSignal.contribute(ctx(Set.of("web")), board);

    // Cleartext HTTP is authoritative — it stays dominant.
    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.WEB_SERVER);
  }

  @Test
  void tlsOnlyRole_withNoContraryEvidence_classifiesWebServer() {
    ScoreBoard board = new ScoreBoard();
    apiSignal.contribute(ctx(Set.of("tls")), board);
    webSignal.contribute(ctx(Set.of("tls")), board);

    // #496 AC #3 — TLS is evidence toward a web role; with nothing contrary it wins.
    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.WEB_SERVER);
    assertThat(board.scores()).containsEntry(DeviceTypes.WEB_SERVER, WebServerSignal.WEIGHT_TLS);
  }

  @Test
  void tlsOnlyRole_losesToStrongRouterHardware() {
    ScoreBoard board = new ScoreBoard();
    // Router OUI (+40) + TTL 255 (+30) + high fan-out (+35) = 105, the AC #6 scenario.
    board.add(DeviceTypes.ROUTER, 105, "router OUI + TTL 255 + fan-out");
    apiSignal.contribute(ctx(Set.of("tls")), board);
    webSignal.contribute(ctx(Set.of("tls")), board);

    // #496 AC #6 — a router serving its own admin UI over TLS classifies as Router, not Web Server.
    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.ROUTER);
  }

  @Test
  void httpEvidence_outranksTlsEvidence_whenBothPresent() {
    ScoreBoard board = new ScoreBoard();
    webSignal.contribute(ctx(Set.of("web", "tls")), board);

    // HTTP is authoritative; the vote is the HTTP weight, not the TLS weight, and not both summed.
    assertThat(board.scores()).containsEntry(DeviceTypes.WEB_SERVER, WebServerSignal.WEIGHT_HTTP);
  }

  @Test
  void noWebRole_addsNothing() {
    ScoreBoard board = new ScoreBoard();
    apiSignal.contribute(ctx(Set.of("dns")), board);
    webSignal.contribute(ctx(Set.of("dns")), board);

    assertThat(board.scores()).isEmpty();
  }
}
