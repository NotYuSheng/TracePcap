package com.tracepcap.hostlog.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.tracepcap.analysis.spi.HostServiceLogResult;
import com.tracepcap.analysis.spi.ServiceLogRoles;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.hostlog.entity.HttpEndpointLogEntity;
import com.tracepcap.hostlog.repository.HttpEndpointLogRepository;
import java.io.File;
import java.net.URISyntaxException;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Runs {@link WebServerLogExtractor#extractAndPersist} against a real capture through real
 * {@code tshark} — every other test of this extraction/scan pair ({@link WebServerLogExtractorTest},
 * {@link WebServerRoleScannerTest}) feeds hand-built rows or in-memory tallies straight to the pure
 * parsing/scanning methods, which proves the logic but not that real tshark output actually matches
 * the field layout those methods assume.
 *
 * <p>{@code fixtures/webserver-roles.pcap} is not synthetic: it is three real captures sliced and
 * merged with {@code mergecap} — {@code http_demo.pcap} for the HTTP traffic, and two ServerHello
 * frames carved out of {@code zoom.pcap} for the TLS traffic (one on a web-facing port, one not).
 * That gives one small (~18 KB) fixture that exercises every role branch with genuine packets:
 *
 * <ul>
 *   <li>{@code 10.0.0.50} — JSON responses only → {@code api}
 *   <li>{@code 10.0.0.60}, {@code 10.0.0.70} — HTML responses → {@code web}
 *   <li>{@code 52.202.62.238:443} — TLS ServerHello, no HTTP seen → {@code tls} (web-facing port)
 *   <li>{@code 167.99.215.164:4434} — TLS ServerHello on a non-web port → no role at all (#496 AC #3)
 * </ul>
 *
 * <p>No Spring context and no database: {@link WebServerLogExtractor} takes only a repository
 * dependency, which is mocked here. This needs a real {@code tshark} on {@code PATH} — see
 * {@code ExternalToolsAvailableTest} (#701), which fails the build loudly if it is missing, rather
 * than letting this degrade to testing nothing.
 */
class WebServerLogExtractorRealCaptureTest {

  @Test
  void realCapture_assignsCorrectRoles_andPersistsHttpEndpoints() throws URISyntaxException {
    HttpEndpointLogRepository repo = mock(HttpEndpointLogRepository.class);
    WebServerLogExtractor extractor = new WebServerLogExtractor(repo);
    FileEntity file = FileEntity.builder().id(UUID.randomUUID()).build();

    File pcap =
        new File(
            getClass().getResource("/fixtures/webserver-roles.pcap").toURI());

    HostServiceLogResult result = extractor.extractAndPersist(file, pcap);

    assertThat(result.roleByServerIp())
        .as("JSON-dominant server is api-like")
        .containsEntry("10.0.0.50", ServiceLogRoles.API);
    assertThat(result.roleByServerIp())
        .as("HTML servers are web, not api")
        .containsEntry("10.0.0.60", ServiceLogRoles.WEB)
        .containsEntry("10.0.0.70", ServiceLogRoles.WEB);
    assertThat(result.roleByServerIp())
        .as("TLS-only server on a web-facing port gets the weaker tls role (#496 AC #4/#6)")
        .containsEntry("52.202.62.238", ServiceLogRoles.TLS);
    assertThat(result.roleByServerIp())
        .as("TLS on a non-web port (SIP-TLS/IMAPS-shaped) contributes no role at all (#496 AC #3)")
        .doesNotContainKey("167.99.215.164");

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<HttpEndpointLogEntity>> saved = ArgumentCaptor.forClass(List.class);
    verify(repo).saveAll(saved.capture());
    assertThat(saved.getValue())
        .as("every persisted row belongs to one of the three real HTTP servers")
        .allSatisfy(
            row ->
                assertThat(row.getServerIp())
                    .isIn("10.0.0.50", "10.0.0.60", "10.0.0.70"));
    assertThat(saved.getValue())
        .as("the api server's rows carry the JSON content type tshark actually reported")
        .filteredOn(row -> row.getServerIp().equals("10.0.0.50"))
        .isNotEmpty()
        .allSatisfy(row -> assertThat(row.getContentType()).isEqualTo("application/json"));
  }
}
