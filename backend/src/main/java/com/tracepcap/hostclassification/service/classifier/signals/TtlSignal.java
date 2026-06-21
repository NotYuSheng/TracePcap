package com.tracepcap.hostclassification.service.classifier.signals;

import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import org.springframework.stereotype.Component;

/**
 * TTL fingerprinting: the initial TTL (normalised to 64/128/255) hints at the OS family — Windows
 * (128) → laptop/desktop, network devices (255) → router, Linux/Unix/Android/iOS (64) → server,
 * mobile or router (weak, splits its weight three ways).
 */
@Component
public class TtlSignal implements DeviceClassificationSignal {

  @Override
  public String name() {
    return "ttl";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    if (ctx.ttl() == null) return;
    int normalised = normaliseTtl(ctx.ttl());
    if (normalised == 128) {
      board.add(DeviceTypes.LAPTOP_DESKTOP, 30, "TTL " + ctx.ttl() + " (Windows range) → +30");
    } else if (normalised == 64) {
      board.add(DeviceTypes.SERVER, 10, "TTL " + ctx.ttl() + " (Linux/iOS/Android range) → +10");
      board.add(DeviceTypes.MOBILE, 10, "TTL " + ctx.ttl() + " (Linux/iOS/Android range) → +10");
      board.add(DeviceTypes.ROUTER, 10, "TTL " + ctx.ttl() + " (Linux/iOS/Android range) → +10");
    } else if (normalised == 255) {
      board.add(DeviceTypes.ROUTER, 30, "TTL " + ctx.ttl() + " (network device range) → +30");
    }
  }

  /**
   * Normalises an observed IP TTL to the most likely initial value (64, 128, or 255). The initial
   * TTL decrements by 1 per hop, so we pick the nearest standard value that is >= the observed value.
   */
  private int normaliseTtl(int ttl) {
    if (ttl > 128) return 255;
    if (ttl > 64) return 128;
    return 64;
  }
}
