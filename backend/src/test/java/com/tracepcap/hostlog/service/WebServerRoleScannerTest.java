package com.tracepcap.hostlog.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ServiceLogRoles;
import com.tracepcap.hostlog.service.WebServerLogExtractor.WebServerStats;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link WebServerRoleScanner} — the Scan-stage decision split out of {@link
 * WebServerLogExtractor} (#512 criterion 8, #496).
 */
class WebServerRoleScannerTest {

  private static WebServerStats stats(boolean json, boolean html, boolean apiPath, boolean writeVerb) {
    WebServerStats s = new WebServerStats();
    s.jsonResponses = json ? 1 : 0;
    s.htmlResponses = html ? 1 : 0;
    s.hasApiPath = apiPath;
    s.hasWriteVerb = writeVerb;
    return s;
  }

  @Test
  void tlsServerHello_countsOnlyOnWebFacingPorts() {
    // #496 AC #3 — TLS is port-qualified: 443/4433/8443 are web-facing; SIP-TLS/IMAPS and null are not.
    assertThat(WebServerRoleScanner.isWebFacingTlsPort(443)).isTrue();
    assertThat(WebServerRoleScanner.isWebFacingTlsPort(8443)).isTrue();
    assertThat(WebServerRoleScanner.isWebFacingTlsPort(4433)).isTrue();
    assertThat(WebServerRoleScanner.isWebFacingTlsPort(5061)).isFalse(); // SIP-TLS
    assertThat(WebServerRoleScanner.isWebFacingTlsPort(993)).isFalse(); // IMAPS
    assertThat(WebServerRoleScanner.isWebFacingTlsPort(null)).isFalse();
  }

  @Test
  void httpServerWithJsonDominantResponses_isApi() {
    Map<String, WebServerStats> serverStats = new LinkedHashMap<>();
    serverStats.put("10.0.0.1", stats(true, false, false, false));

    Map<String, String> roles = WebServerRoleScanner.assignRoles(serverStats, Map.of());

    assertThat(roles).containsEntry("10.0.0.1", ServiceLogRoles.API);
  }

  @Test
  void plainHtmlServer_isWeb() {
    Map<String, WebServerStats> serverStats = new LinkedHashMap<>();
    serverStats.put("10.0.0.2", stats(false, true, false, false));

    Map<String, String> roles = WebServerRoleScanner.assignRoles(serverStats, Map.of());

    assertThat(roles).containsEntry("10.0.0.2", ServiceLogRoles.WEB);
  }

  @Test
  void tlsOnlyServer_getsTheWeakerTlsRole() {
    // No HTTP observed at all for this IP — only a web-facing TLS handshake.
    Map<String, String> roles =
        WebServerRoleScanner.assignRoles(Map.of(), Map.of("10.0.0.3", Set.of(443)));

    assertThat(roles).containsEntry("10.0.0.3", ServiceLogRoles.TLS);
  }

  @Test
  void tlsOnNonWebPort_contributesNoRoleAtAll() {
    // SIP-TLS on 5061 — a TLS service, but not web evidence (#496 AC #3).
    Map<String, String> roles =
        WebServerRoleScanner.assignRoles(Map.of(), Map.of("10.0.0.4", Set.of(5061)));

    assertThat(roles).doesNotContainKey("10.0.0.4");
  }

  @Test
  void httpRoleWinsOverTlsForTheSameServer() {
    // A server that served real HTTP is authoritatively "web"/"api" — TLS is not even weaker
    // evidence once real evidence exists, since putIfAbsent must not override the HTTP verdict.
    Map<String, WebServerStats> serverStats = new LinkedHashMap<>();
    serverStats.put("10.0.0.5", stats(false, true, false, false));

    Map<String, String> roles =
        WebServerRoleScanner.assignRoles(serverStats, Map.of("10.0.0.5", Set.of(443)));

    assertThat(roles).containsEntry("10.0.0.5", ServiceLogRoles.WEB);
  }
}
