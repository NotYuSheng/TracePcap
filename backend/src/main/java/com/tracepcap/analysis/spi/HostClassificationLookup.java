package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.UUID;

/**
 * Read port for per-file host classifications (#512 slice 5): the scan output downstream stages
 * consume without reaching into {@code analysis}' repositories or entities. The runner-up fields
 * expose how close second place was — adjudication needs the contest, not just the argmax.
 */
public interface HostClassificationLookup {

  record ClassifiedHost(
      String ip,
      String deviceType,
      int confidence,
      Integer winnerScore,
      String runnerUpType,
      Integer runnerUpScore) {}

  /** Never contains null elements — the adapter maps each persisted row to a fresh record. */
  List<ClassifiedHost> classifiedHosts(UUID fileId);
}
