package com.tracepcap.hostclassification.service.classifier.signals;

import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import com.tracepcap.analysis.spi.ServiceLogRoles;
import org.springframework.stereotype.Component;

/**
 * Votes {@code WEB_SERVER}, graded by how strong the evidence is (#496 AC #4/#6):
 *
 * <ul>
 *   <li><b>{@code web} role — served cleartext HTTP.</b> Authoritative observed evidence, like
 *       {@link DnsServerSignal}: it carries a dominant weight that outranks the heuristic signals.
 *   <li><b>{@code tls} role — completed a TLS ServerHello on a web port, no HTTP seen.</b> Real but
 *       weaker: every router admin UI and IoT control channel terminates TLS. A moderate weight, so
 *       strong contrary hardware evidence (router OUI + TTL 255 + high fan-out) can outrank it and a
 *       close call renders <em>contested</em> rather than a false-confident Web Server.
 * </ul>
 *
 * API-like HTTP servers are tagged {@code api} instead of {@code web}/{@code tls} (see {@link
 * ApiServerSignal}), so this never double-counts them.
 */
@Component
public class WebServerSignal implements DeviceClassificationSignal {

  /** Cleartext HTTP served — authoritative, dominant (mirrors {@link DnsServerSignal}). */
  static final int WEIGHT_HTTP = 1000;

  /**
   * TLS-only, port-qualified — evidence toward, not proof. Sits in the band (45, 105): above the
   * "answers-only on a well-known port" SERVER vote (35) + TTL (10) so a genuine HTTPS-only host
   * still leans WEB_SERVER, yet below router hardware (OUI 40 + TTL 255 → 30 = 70, or + fan-out 35 =
   * 105) so a router serving its own admin UI over TLS resolves to ROUTER.
   */
  static final int WEIGHT_TLS = 60;

  @Override
  public String name() {
    return "web-server";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    if (ctx.hasServiceRole(ServiceLogRoles.WEB)) {
      board.add(DeviceTypes.WEB_SERVER, WEIGHT_HTTP, "Served HTTP → +" + WEIGHT_HTTP);
    } else if (ctx.hasServiceRole(ServiceLogRoles.TLS)) {
      board.add(
          DeviceTypes.WEB_SERVER, WEIGHT_TLS, "Served TLS on a web port → +" + WEIGHT_TLS);
    }
  }
}
