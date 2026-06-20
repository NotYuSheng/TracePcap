package com.tracepcap.analysis.service.classifier.signals;

import com.tracepcap.analysis.service.classifier.DeviceClassificationSignal;
import com.tracepcap.analysis.service.classifier.HostContext;
import com.tracepcap.analysis.service.classifier.ScoreBoard;
import org.springframework.stereotype.Component;

/**
 * Votes for the device type hinted by the host's MAC OUI vendor (e.g. Cisco → router, Apple →
 * mobile). The single largest signal at +40, since a resolved vendor is strong evidence.
 */
@Component
public class OuiHintSignal implements DeviceClassificationSignal {

  static final int WEIGHT = 40;

  @Override
  public String name() {
    return "oui-hint";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    if (ctx.ouiHint() != null) {
      board.add(
          ctx.ouiHint(),
          WEIGHT,
          "MAC OUI matched \"" + ctx.manufacturer() + "\" → +" + WEIGHT);
    }
  }
}
