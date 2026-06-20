package com.tracepcap.analysis.service.classifier;

/**
 * A pluggable contributor to device classification. Each implementation inspects a {@link HostContext}
 * and votes weighted points toward one or more device types via the {@link ScoreBoard}.
 *
 * <p>This is the extension seam for the classifier: {@code DeviceClassifierService} injects every
 * {@code DeviceClassificationSignal} bean and runs them all, so adding a new signal (or a new device
 * type to vote for) is just adding a {@code @Component} — no change to the classifier core. Signals
 * must be side-effect free and never throw.
 */
public interface DeviceClassificationSignal {

  /** Stable identifier for logging/debugging, e.g. {@code "oui-hint"}, {@code "dns-server"}. */
  String name();

  /** Inspects the host and adds weighted votes (with reasons) to the score board. */
  void contribute(HostContext ctx, ScoreBoard board);
}
