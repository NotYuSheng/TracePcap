package com.tracepcap.common.stage;

/**
 * Whether the threat-detection engine is already loaded (#569).
 *
 * <p>A port because the answer changes an estimate by a factor of twenty and the module that needs
 * it lives outside {@code analysis}: Suricata's ruleset build costs ~45 s once per process, so a
 * capture that has to pay it is a different job from one that does not, and the ETA shown at upload
 * has to say which (#758).
 *
 * <p>In {@code common} rather than {@code analysis.spi} because {@code analysis} already depends on
 * {@code file} — putting it there would close the {@code analysis <-> file} cycle that #512 slice 1
 * was written to break. Both sides depend on this instead, the same arrangement as
 * {@code common.net.LocalityPolicy}.
 */
@FunctionalInterface
public interface DetectionEngineStatus {

  /** True when the next capture can skip the one-time engine build. */
  boolean isWarm();
}
