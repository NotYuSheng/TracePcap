package com.tracepcap.hostlog.service;

import com.tracepcap.analysis.spi.ServiceLogRoles;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Judges whether a host observed serving HTTP/TLS is a web server, an API server, or (weaker
 * evidence) merely TLS-capable — the decision {@link WebServerLogExtractor} used to make inline
 * (#512, #496).
 *
 * <p>This is the Scan half of a split that used to be one class: {@link WebServerLogExtractor}
 * extracts — it runs the tshark passes, tallies per-server observations, and persists {@code
 * HttpEndpointLogEntity} rows — and hands this class the tallies. Nothing here touches the pcap or
 * a tshark process; it only reads the facts the extractor already gathered. That is the boundary
 * {@code analysis.spi.Extractor}'s javadoc names directly: <em>"'port 443 carried TLS' is
 * extraction, 'this host is a web server' is a Scan-stage conclusion. Mixing the two is what
 * WebServerLogExtractor does wrong today, and #496 is the bill for it."</em>
 *
 * <p>Not wired to the {@code story.spi.Scanner} interface: that SPI is shaped for the
 * narrative/investigation pipeline (it returns {@code Finding}s over conversation-level facts) and
 * has no notion of a per-server role map, which is what {@code HostServiceLogExtractor}'s contract
 * requires. Rather than bend one SPI to fit a shape it wasn't designed for, this stays a plain,
 * single-consumer class in the same module as the facts it reads — the same reasoning #734 already
 * applied to {@code ConversationLookup}: an abstraction serving one caller is not paying for itself.
 */
final class WebServerRoleScanner {

  private WebServerRoleScanner() {}

  /**
   * TLS server ports that count as web-facing. A ServerHello on one of these is evidence toward a
   * web role; a ServerHello on any other port (SIP-TLS 5061, IMAPS 993, …) is a TLS service but not
   * a web server, so it contributes no web evidence at all (#496 AC #3 — port-qualified, not "any
   * port"). Which ports mean "web" is a judgment call, not an observation, which is why it lives
   * here rather than filtering what the extractor records.
   */
  private static final Set<Integer> WEB_TLS_PORTS = Set.of(443, 4433, 8443);

  /**
   * Assigns each server a role from what the extractor observed: api-like HTTP servers → {@code
   * "api"}, other HTTP servers → {@code "web"} (authoritative — they served HTTP). Servers seen
   * only completing a web-facing TLS handshake, with no cleartext HTTP observed at all, get the
   * weaker {@code "tls"} role: real evidence toward a web role, but not proof that outranks
   * contrary hardware evidence (#496 AC #4/#6).
   *
   * @param serverStats per-server HTTP response-shape tallies from the HTTP pass
   * @param tlsHandshakePortsByIp every port each IP completed a TLS ServerHello on, unfiltered —
   *     the raw observation; this method is what decides which of those ports mean "web"
   */
  static Map<String, String> assignRoles(
      Map<String, WebServerLogExtractor.WebServerStats> serverStats,
      Map<String, Set<Integer>> tlsHandshakePortsByIp) {
    Map<String, String> roleByServerIp = new LinkedHashMap<>();
    for (Map.Entry<String, WebServerLogExtractor.WebServerStats> e : serverStats.entrySet()) {
      roleByServerIp.put(
          e.getKey(), isApiLike(e.getValue()) ? ServiceLogRoles.API : ServiceLogRoles.WEB);
    }
    for (Map.Entry<String, Set<Integer>> e : tlsHandshakePortsByIp.entrySet()) {
      if (e.getValue().stream().anyMatch(WebServerRoleScanner::isWebFacingTlsPort)) {
        roleByServerIp.putIfAbsent(e.getKey(), ServiceLogRoles.TLS);
      }
    }
    return roleByServerIp;
  }

  /**
   * Whether a TLS ServerHello on this port counts as web evidence (#496 AC #3). Only web-facing TLS
   * ports qualify; a null port or a non-web port (SIP-TLS, IMAPS, …) is not a web server.
   */
  static boolean isWebFacingTlsPort(Integer port) {
    return port != null && WEB_TLS_PORTS.contains(port);
  }

  /** A server is "API-like" when JSON dominates its responses, or it uses REST write verbs / api paths. */
  static boolean isApiLike(WebServerLogExtractor.WebServerStats s) {
    boolean jsonDominant = s.jsonResponses > 0 && s.jsonResponses >= s.htmlResponses;
    return jsonDominant || s.hasApiPath || s.hasWriteVerb;
  }
}
