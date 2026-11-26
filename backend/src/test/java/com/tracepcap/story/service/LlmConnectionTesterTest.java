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
      byte[] body = (authorised ? "{\"data\":[{\"id\":\"qwen\",\"max_model_len\":32768},{\"id\":\"llama\"}]}" : "{}").getBytes(StandardCharsets.UTF_8);
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
      @Override public int maxTokens() { return 0; }
    };
    PolicyEditGate gate = new PolicyEditGate() {
      @Override public boolean canEdit(EditablePolicy.Kind kind) { return allowed; }
      @Override public String reason(EditablePolicy.Kind kind) { return "Only admins can change the LLM connection."; }
    };
    return new LlmConnectionTester(settings, gate, new ObjectMapper(), new com.tracepcap.config.LlmConfig());
  }

  private static String statuses(LlmTestResult r) {
    return String.join(",", r.getSteps().stream().map(s -> s.getKey() + "=" + s.getStatus()).toList());
  }

  @Test
  void theCurrentSettingsPassEveryStepAndListTheModels() {
    LlmTestResult r = tester(true).test(new LlmTestRequest());
    assertThat(statuses(r)).isEqualTo("reach=OK,key=OK,model=OK,reply=OK,capacity=OK");
    assertThat(r.isOk()).isTrue();
    assertThat(r.getModels()).containsExactly("qwen", "llama");
    assertThat(r.getSteps().get(4).getDetail()).contains("32,768 tokens");
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

  @Test
  void listsTheServersModelsWithTheirContext() {
    LlmConnectionTester.ModelList list = tester(true).listModels(new LlmTestRequest(url, "good", null));
    assertThat(list.ok()).isTrue();
    assertThat(list.models())
        .containsExactly(new LlmConnectionTester.ModelOption("qwen", 32768), new LlmConnectionTester.ModelOption("llama", null));
  }

  @Test
  void listingWithARefusedKeySaysSo() {
    LlmConnectionTester.ModelList list = tester(true).listModels(new LlmTestRequest(null, "bad", null));
    assertThat(list.ok()).isFalse();
    assertThat(list.detail()).contains("refused the key");
  }

  @Test
  void listingOtherValuesTakesThePermissionToChangeThem() {
    assertThat(tester(false).listModels(new LlmTestRequest()).ok()).isTrue();
    assertThatThrownBy(() -> tester(false).listModels(new LlmTestRequest("http://elsewhere.test/v1", null, null)))
        .isInstanceOf(ForbiddenException.class);
  }

  @Test
  void aSmallContextIsWarnedOf_andMoreSoForAReasoningModel() {
    var small = LlmConnectionTester.capacityStep(8192, false, null, 0, 0, 300);
    assertThat(small.getStatus()).isEqualTo("WARN");
    assertThat(small.getDetail()).contains("8,192 tokens").contains("may be refused");

    var thinking = LlmConnectionTester.capacityStep(20_000, true, null, 0, 0, 300);
    assertThat(thinking.getStatus()).isEqualTo("WARN");
    assertThat(thinking.getDetail()).contains("reasoning model");

    assertThat(LlmConnectionTester.capacityStep(20_000, false, null, 0, 0, 300).getStatus()).isEqualTo("OK");
  }

  @Test
  void aCapTooLowForAStoryIsWarnedOf() {
    var capped = LlmConnectionTester.capacityStep(131_072, true, null, 0, 8000, 300);
    assertThat(capped.getStatus()).isEqualTo("WARN");
    assertThat(capped.getDetail()).contains("LLM_MAX_TOKENS caps replies at 8,000").contains("24,000");
    assertThat(LlmConnectionTester.capacityStep(131_072, false, null, 0, 8000, 300).getStatus()).isEqualTo("OK");
  }

  @Test
  void aModelTooSlowForTheTimeoutIsWarnedOf() {
    // 24 tokens in 4.8 s: 5 a second, so a 4000-token story takes 800 s against a 300 s timeout.
    var slow = LlmConnectionTester.capacityStep(131_072, false, 24, 4_800, 0, 300);
    assertThat(slow.getStatus()).isEqualTo("WARN");
    assertThat(slow.getDetail()).contains("about 5 tokens a second").contains("13 minutes").contains("LLM_TIMEOUT to 860");

    var fast = LlmConnectionTester.capacityStep(131_072, false, 24, 480, 0, 300);
    assertThat(fast.getStatus()).isEqualTo("OK");
    assertThat(fast.getDetail()).contains("about 50 tokens a second").contains("80 s");
  }

  @Test
  void anUnknownContextIsNotedNotWarnedOf() {
    var unknown = LlmConnectionTester.capacityStep(null, false, null, 0, 0, 300);
    assertThat(unknown.getStatus()).isEqualTo("OK");
    assertThat(unknown.getDetail()).contains("LLM_CONTEXT_LENGTH");
  }

  @Test
  void aReplyTooShortToTimeGivesNoSpeed() {
    // "OK" in 400 ms says nothing about how fast it writes a story.
    var shortReply = LlmConnectionTester.capacityStep(131_072, false, 2, 400, 0, 300);
    assertThat(shortReply.getStatus()).isEqualTo("OK");
    assertThat(shortReply.getDetail()).doesNotContain("tokens a second");
  }

  @Test
  void anUnknownContextSaysWhatRepliesGet() {
    assertThat(LlmConnectionTester.capacityStep(null, false, null, 0, 6000, 300).getDetail())
        .contains("6,000 tokens (LLM_MAX_TOKENS)");
    assertThat(LlmConnectionTester.capacityStep(null, false, null, 0, 0, 300).getDetail())
        .contains("8,192 tokens, then the rest");
  }
}
