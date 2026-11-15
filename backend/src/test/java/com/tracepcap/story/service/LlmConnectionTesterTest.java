package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.common.settings.EditablePolicy;
import com.tracepcap.common.settings.LlmSettings;
import com.tracepcap.common.settings.PolicyEditGate;
import com.tracepcap.story.dto.LlmTestRequest;
import com.tracepcap.story.dto.LlmTestResult;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The connection test against a small fake OpenAI-compatible server: each step's verdict. */
class LlmConnectionTesterTest {

  private HttpServer server;
  private String url;

  @BeforeEach
  void start() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/models", ex -> {
      boolean authorised = "Bearer good".equals(ex.getRequestHeaders().getFirst("Authorization"));
      byte[] body = (authorised ? "{\"data\":[{\"id\":\"qwen\"},{\"id\":\"llama\"}]}" : "{}").getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(authorised ? 200 : 401, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.createContext("/v1/chat/completions", ex -> {
      byte[] body = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"OK\"}}]}".getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(200, body.length);
      ex.getResponseBody().write(body);
      ex.close();
    });
    server.start();
    url = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1";
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  private LlmConnectionTester tester(boolean allowed) {
    LlmSettings settings = new LlmSettings(null) {
      @Override public String baseUrl() { return url; }
      @Override public String apiKey() { return "good"; }
      @Override public String model() { return "qwen"; }
      @Override public int timeoutSeconds() { return 30; }
    };
    PolicyEditGate gate = new PolicyEditGate() {
      @Override public boolean canEdit(EditablePolicy.Kind kind) { return allowed; }
      @Override public String reason(EditablePolicy.Kind kind) { return "Only admins can change the LLM connection."; }
    };
    return new LlmConnectionTester(settings, gate, new ObjectMapper());
  }

  private static String statuses(LlmTestResult r) {
    return String.join(",", r.getSteps().stream().map(s -> s.getKey() + "=" + s.getStatus()).toList());
  }

  @Test
  void theCurrentSettingsPassEveryStepAndListTheModels() {
    LlmTestResult r = tester(true).test(new LlmTestRequest());
    assertThat(statuses(r)).isEqualTo("reach=OK,key=OK,model=OK,reply=OK");
    assertThat(r.isOk()).isTrue();
    assertThat(r.getModels()).containsExactly("qwen", "llama");
  }

  @Test
  void aRefusedKeyStopsBeforeTheModel() {
    LlmTestResult r = tester(true).test(new LlmTestRequest(null, "bad", null));
    assertThat(statuses(r)).isEqualTo("reach=OK,key=FAIL,model=SKIPPED,reply=SKIPPED");
    assertThat(r.isOk()).isFalse();
  }

  @Test
  void aModelTheServerDoesntHaveSaysSoAndOffersItsModels() {
    LlmTestResult r = tester(true).test(new LlmTestRequest(null, null, "gpt-4"));
    assertThat(statuses(r)).isEqualTo("reach=OK,key=OK,model=FAIL,reply=SKIPPED");
    assertThat(r.getModels()).contains("qwen");
  }

  @Test
  void anUnreachableServerFailsTheFirstStep() {
    LlmTestResult r = tester(true).test(new LlmTestRequest("http://127.0.0.1:1/v1", null, null));
    assertThat(statuses(r)).isEqualTo("reach=FAIL,key=SKIPPED,model=SKIPPED,reply=SKIPPED");
  }

  @Test
  void anyoneCanTestWhatsInEffect_onlyThoseWhoMayChangeItCanTestOtherValues() {
    assertThat(tester(false).test(new LlmTestRequest()).isOk()).isTrue();
    assertThatThrownBy(() -> tester(false).test(new LlmTestRequest("http://elsewhere.test/v1", null, null)))
        .isInstanceOf(ForbiddenException.class);
  }
}
