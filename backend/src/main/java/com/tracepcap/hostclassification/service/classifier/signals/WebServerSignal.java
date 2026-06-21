package com.tracepcap.hostclassification.service.classifier.signals;

import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import com.tracepcap.analysis.spi.ServiceLogRoles;
import org.springframework.stereotype.Component;

/**
 * Classifies a host as a {@code WEB_SERVER} when it was observed serving HTTP/TLS but not in an
 * API-like way (see {@link com.tracepcap.hostclassification.service.classifier.signals.ApiServerSignal}). Like
 * {@link DnsServerSignal}, this is authoritative observed evidence, so it carries a dominant weight
 * that outranks the heuristic signals.
 */
@Component
public class WebServerSignal implements DeviceClassificationSignal {

  static final int WEIGHT = 1000;

  @Override
  public String name() {
    return "web-server";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    if (ctx.hasServiceRole(ServiceLogRoles.WEB)) {
      board.add(DeviceTypes.WEB_SERVER, WEIGHT, "Served HTTP/TLS → +" + WEIGHT);
    }
  }
}
