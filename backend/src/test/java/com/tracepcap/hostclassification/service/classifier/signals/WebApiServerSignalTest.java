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

    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.WEB_SERVER);
  }

  @Test
  void noWebRole_addsNothing() {
    ScoreBoard board = new ScoreBoard();
    apiSignal.contribute(ctx(Set.of("dns")), board);
    webSignal.contribute(ctx(Set.of("dns")), board);

    assertThat(board.scores()).isEmpty();
  }
}
