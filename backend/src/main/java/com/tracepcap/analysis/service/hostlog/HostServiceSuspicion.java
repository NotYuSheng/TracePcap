package com.tracepcap.analysis.service.hostlog;

/**
 * A server host flagged as suspicious by a {@link HostServiceLogExtractor}.
 *
 * @param ip the server IP that behaved anomalously
 * @param role the service role that raised the flag (e.g. {@code "dns"})
 * @param reason short human-readable explanation (e.g. {@code "62% NXDOMAIN over 134 queries"})
 */
public record HostServiceSuspicion(String ip, String role, String reason) {}
