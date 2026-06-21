package com.tracepcap.hostclassification.service.classifier.signals;

import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import com.tracepcap.analysis.spi.ServiceLogRoles;
import org.springframework.stereotype.Component;

/**
 * Classifies a host as an {@code API_SERVER} when it served HTTP in an API-like way (JSON responses,
 * REST write verbs, or {@code /api}-style paths — decided by {@code WebServerLogExtractor}). Like
 * {@link DnsServerSignal}, this is authoritative observed evidence with a dominant weight so it wins
 * over the heuristic signals. A host is tagged {@code api} <em>or</em> {@code web}, never both, so
 * this and {@link WebServerSignal} don't collide.
 */
@Component
public class ApiServerSignal implements DeviceClassificationSignal {

  static final int WEIGHT = 1000;

  @Override
  public String name() {
    return "api-server";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    if (ctx.hasServiceRole(ServiceLogRoles.API)) {
      board.add(DeviceTypes.API_SERVER, WEIGHT, "Served an HTTP API → +" + WEIGHT);
    }
  }
}
