package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.Map;

/**
 * Outcome of running a {@link HostServiceLogExtractor} over a capture.
 *
 * @param roleByServerIp the role each detected server plays for this extractor, keyed by IP (e.g.
 *     every DNS responder → {@code "dns"}; a web host → {@code "api"} or {@code "web"}). Drives
 *     per-host service tagging and device classification. A single extractor may assign different
 *     roles to different hosts.
 * @param suspicions servers that exhibited anomalous behaviour for this role
 */
public record HostServiceLogResult(
    Map<String, String> roleByServerIp, List<HostServiceSuspicion> suspicions) {

  public static HostServiceLogResult empty() {
    return new HostServiceLogResult(Map.of(), List.of());
  }
}
