package com.tracepcap.analysis.service.classifier.signals;

import com.tracepcap.analysis.service.classifier.DeviceClassificationSignal;
import com.tracepcap.analysis.service.classifier.DeviceTypes;
import com.tracepcap.analysis.service.classifier.HostContext;
import com.tracepcap.analysis.service.classifier.ScoreBoard;
import com.tracepcap.analysis.service.hostlog.DnsQueryLogExtractor;
import org.springframework.stereotype.Component;

/**
 * Classifies a host as a {@code DNS_SERVER} when it was observed answering DNS queries (the {@code
 * dns} service role, detected by {@link DnsQueryLogExtractor}). This is authoritative evidence — the
 * host actually served DNS — so it carries a strong weight that outranks the heuristic signals,
 * making a resolver classify as a DNS server rather than a generic SERVER/ROUTER.
 *
 * <p>Template for future service roles: a web/API server would add an analogous signal voting for an
 * {@code API_SERVER} type on its own role.
 */
@Component
public class DnsServerSignal implements DeviceClassificationSignal {

  static final int WEIGHT = 60;

  @Override
  public String name() {
    return "dns-server";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    if (ctx.hasServiceRole(DnsQueryLogExtractor.ROLE)) {
      board.add(DeviceTypes.DNS_SERVER, WEIGHT, "Answered DNS queries → +" + WEIGHT);
    }
  }
}
