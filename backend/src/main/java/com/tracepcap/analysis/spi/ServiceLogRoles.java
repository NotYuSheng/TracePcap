package com.tracepcap.analysis.spi;

/**
 * Canonical service-role identifiers reported by {@link HostServiceLogExtractor} implementations and
 * consumed across modules (the ingest pipeline, device-classification signals, and network
 * intelligence). Kept in the SPI as shared vocabulary so consumers depend on this contract rather
 * than on a concrete extractor in the {@code hostlog} module.
 */
public final class ServiceLogRoles {

  private ServiceLogRoles() {}

  /** Host acts as a DNS resolver. */
  public static final String DNS = "dns";

  /** Host serves web (HTML/TLS) content. */
  public static final String WEB = "web";

  /** Host serves API-like (JSON/REST) responses. */
  public static final String API = "api";
}
