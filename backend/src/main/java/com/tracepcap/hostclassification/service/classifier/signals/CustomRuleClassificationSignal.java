package com.tracepcap.hostclassification.service.classifier.signals;

import com.tracepcap.analysis.spi.ClassificationHint;
import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import org.springframework.stereotype.Component;

/**
 * Detection rules' classification hints (#926): "hosts matching rtsp_camera are probably a CCTV
 * Camera". Each matched rule that carries one adds its weight to that type, with the rule named in
 * the evidence. It's a vote like any other signal, so strong contrary evidence can still win, and a
 * human label overrides the result as usual.
 */
@Component
public class CustomRuleClassificationSignal implements DeviceClassificationSignal {

  @Override
  public String name() {
    return "custom-rule";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    for (ClassificationHint h : ctx.ruleHints()) {
      if (h.deviceType() == null || h.deviceType().isBlank() || h.weight() <= 0) continue;
      board.add(
          h.deviceType(),
          h.weight(),
          "Custom rule \"" + h.source() + "\" → " + h.deviceType() + " +" + h.weight());
    }
  }
}
