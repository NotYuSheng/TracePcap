package com.tracepcap.analysis.service.hostlog;

import java.util.List;
import java.util.Set;

/**
 * Outcome of running a {@link HostServiceLogExtractor} over a capture.
 *
 * @param serverIps the IPs detected serving this role (e.g. every host that answered DNS) — used to
 *     tag hosts with their service roles and drive device classification
 * @param suspicions servers that exhibited anomalous behaviour for this role
 */
public record HostServiceLogResult(Set<String> serverIps, List<HostServiceSuspicion> suspicions) {

  public static HostServiceLogResult empty() {
    return new HostServiceLogResult(Set.of(), List.of());
  }
}
