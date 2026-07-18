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

  /** Host serves cleartext web (HTML) content — observed HTTP responses. */
  public static final String WEB = "web";

  /** Host serves API-like (JSON/REST) responses. */
  public static final String API = "api";

  /**
   * Host completed a TLS handshake as the server (sent a ServerHello) on a web-facing port, but no
   * cleartext HTTP was observed. Weaker, port-qualified evidence toward a web role than {@link #WEB}
   * — any router admin UI or IoT control channel terminates TLS, so on its own it must not force a
   * Web Server verdict over contrary hardware evidence (#496).
   */
  public static final String TLS = "tls";
}
