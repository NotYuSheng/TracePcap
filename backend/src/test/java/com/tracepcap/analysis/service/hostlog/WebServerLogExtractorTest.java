package com.tracepcap.analysis.service.hostlog;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.service.hostlog.WebServerLogExtractor.EndpointAgg;
import com.tracepcap.analysis.service.hostlog.WebServerLogExtractor.WebServerStats;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link WebServerLogExtractor#parseHttpFrame} (request→response correlation) and the
 * api/web heuristic. tshark {@code http} fields are pipe-split:
 * {@code tcp.stream | ip.src | ip.dst | method | uri | status | content_type | server}.
 */
class WebServerLogExtractorTest {

  private Map<String, EndpointAgg> endpoints;
  private Map<String, WebServerStats> serverStats;
  private Map<String, Deque<String[]>> pending;
  private int stream = 0;

  private void init() {
    if (endpoints == null) {
      endpoints = new LinkedHashMap<>();
      serverStats = new LinkedHashMap<>();
      pending = new HashMap<>();
    }
  }

  /** Feeds a matched request frame + response frame on a fresh stream (as tshark would emit them). */
  private void exchange(
      String client, String server, String method, String uri, String status, String ct, String sw) {
    init();
    String s = String.valueOf(stream++);
    WebServerLogExtractor.parseHttpFrame(
        new String[] {s, client, server, method, uri, "", "", ""}, endpoints, serverStats, pending);
    WebServerLogExtractor.parseHttpFrame(
        new String[] {s, server, client, "", uri, status, ct, sw}, endpoints, serverStats, pending);
  }

  @Test
  void matchedExchange_recoversMethodAndPath_andLooksApi() {
    exchange("10.0.0.10", "10.0.0.1", "GET", "/api/users", "200", "application/json", "nginx/1.18.0");

    EndpointAgg agg = endpoints.get("10.0.0.1|GET|/api/users");
    assertThat(agg).isNotNull();
    assertThat(agg.requestCount).isEqualTo(1);
    assertThat(agg.successCount).isEqualTo(1);
    assertThat(agg.statusCounts).containsEntry(200, 1);
    assertThat(agg.contentType).isEqualTo("application/json");
    assertThat(agg.serverSoftware).isEqualTo("nginx/1.18.0");
    assertThat(WebServerLogExtractor.isApiLike(serverStats.get("10.0.0.1"))).isTrue();
  }

  @Test
  void statusClasses_areBucketed() {
    exchange("10.0.0.10", "10.0.0.1", "GET", "/a", "204", "", "");
    exchange("10.0.0.10", "10.0.0.1", "GET", "/b", "404", "", "");
    exchange("10.0.0.10", "10.0.0.1", "GET", "/c", "503", "", "");

    assertThat(endpoints.get("10.0.0.1|GET|/a").successCount).isEqualTo(1);
    assertThat(endpoints.get("10.0.0.1|GET|/b").clientErrorCount).isEqualTo(1);
    assertThat(endpoints.get("10.0.0.1|GET|/c").serverErrorCount).isEqualTo(1);
  }

  @Test
  void queryStringIsStripped_soEndpointsAggregate() {
    exchange("10.0.0.10", "10.0.0.1", "GET", "/search?q=a", "200", "text/html", "");
    exchange("10.0.0.10", "10.0.0.1", "GET", "/search?q=b", "200", "text/html", "");

    EndpointAgg agg = endpoints.get("10.0.0.1|GET|/search");
    assertThat(agg).isNotNull();
    assertThat(agg.requestCount).isEqualTo(2);
  }

  @Test
  void contentTypeCharsetIsStripped() {
    exchange("10.0.0.10", "10.0.0.1", "POST", "/api/login", "200", "application/json; charset=utf-8", "");

    assertThat(endpoints.get("10.0.0.1|POST|/api/login").contentType).isEqualTo("application/json");
  }

  @Test
  void plainHtmlSite_isNotApiLike() {
    exchange("10.0.0.10", "10.0.0.2", "GET", "/", "200", "text/html", "Apache");
    exchange("10.0.0.10", "10.0.0.2", "GET", "/about", "200", "text/html", "Apache");

    assertThat(WebServerLogExtractor.isApiLike(serverStats.get("10.0.0.2"))).isFalse();
  }

  @Test
  void writeVerbMakesServerApiLike() {
    exchange("10.0.0.10", "10.0.0.3", "DELETE", "/things/1", "204", "", "");

    assertThat(serverStats.get("10.0.0.3").hasWriteVerb).isTrue();
    assertThat(WebServerLogExtractor.isApiLike(serverStats.get("10.0.0.3"))).isTrue();
  }

  @Test
  void apiPathMakesServerApiLike_evenWithoutJson() {
    exchange("10.0.0.10", "10.0.0.4", "GET", "/api/health", "200", "text/plain", "");

    assertThat(serverStats.get("10.0.0.4").hasApiPath).isTrue();
    assertThat(WebServerLogExtractor.isApiLike(serverStats.get("10.0.0.4"))).isTrue();
  }

  @Test
  void unmatchedResponse_fallsBackToResponseUri_andCountsTowardServer() {
    init();
    // Lone response frame (no preceding request queued).
    WebServerLogExtractor.parseHttpFrame(
        new String[] {"9", "10.0.0.5", "10.0.0.10", "", "/orphan", "200", "text/html", "nginx"},
        endpoints, serverStats, pending);

    assertThat(endpoints.get("10.0.0.5||/orphan")).isNotNull();
    assertThat(serverStats.get("10.0.0.5").totalResponses).isEqualTo(1);
  }

  @Test
  void repeatedEndpoint_aggregatesCountAndStatuses() {
    exchange("10.0.0.10", "10.0.0.1", "GET", "/api/x", "200", "application/json", "");
    exchange("10.0.0.10", "10.0.0.1", "GET", "/api/x", "200", "application/json", "");
    exchange("10.0.0.10", "10.0.0.1", "GET", "/api/x", "500", "application/json", "");

    EndpointAgg agg = endpoints.get("10.0.0.1|GET|/api/x");
    assertThat(agg.requestCount).isEqualTo(3);
    assertThat(agg.successCount).isEqualTo(2);
    assertThat(agg.serverErrorCount).isEqualTo(1);
    assertThat(WebServerLogExtractor.topStatus(agg.statusCounts)).isEqualTo(200);
  }
}
