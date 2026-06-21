package com.tracepcap.hostclassification.service.classifier.signals;

import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import com.tracepcap.analysis.spi.ServiceLogRoles;
import org.springframework.stereotype.Component;

/**
 * Classifies a host as a {@code DNS_SERVER} when it was observed answering DNS queries (the {@code
 * dns} service role, detected by {@code DnsQueryLogExtractor}). This is authoritative evidence — the
 * host actually served DNS — so it carries a strong weight that outranks the heuristic signals,
 * making a resolver classify as a DNS server rather than a generic SERVER/ROUTER.
 *
 * <p>Template for future service roles: a web/API server would add an analogous signal voting for an
 * {@code API_SERVER} type on its own role.
 */
@Component
public class DnsServerSignal implements DeviceClassificationSignal {

  /**
   * Deliberately dominant: a host that <em>observably answered DNS</em> is a DNS server, so this
   * authoritative evidence outranks the summed heuristic votes (OUI/TTL/app/traffic) which top out
   * far below this. A plain +60 could be overtaken by a busy host that also serves DNS, leaving it
   * mislabelled as SERVER/ROUTER; this guarantees DNS_SERVER wins while staying a normal weighted
   * signal (no special-casing in the classifier core).
   */
  static final int WEIGHT = 1000;

  @Override
  public String name() {
    return "dns-server";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    if (ctx.hasServiceRole(ServiceLogRoles.DNS)) {
      board.add(DeviceTypes.DNS_SERVER, WEIGHT, "Answered DNS queries → +" + WEIGHT);
    }
  }
}
