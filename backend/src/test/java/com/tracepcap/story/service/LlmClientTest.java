package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.tracepcap.common.exception.ContextLengthExceededException;
import com.tracepcap.common.exception.LlmException;
import com.tracepcap.config.LlmConfig;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

/**
 * The wire contract with an OpenAI-compatible server, which nothing covered before #623.
 *
 * <p>The behaviour under test is mostly what happens when the server is <em>worse</em> than the
 * spec — ignores {@code tools}, rejects {@code tool_choice}, 400s on the whole request. Every one
 * of those is a real local backend, and the offline requirement means each has to degrade to the
 * free-text path rather than fail the story.
 */
class LlmClientTest {

  private static final String COMPLETIONS_URL = "http://llm.test/v1/chat/completions";
  private static final String MODELS_URL = "http://llm.test/v1/models";

  private RestTemplate restTemplate;
  private MockRestServiceServer server;
  private MockRestServiceServer healthServer;
  private LlmConfig config;
  private LlmClient client;

  @BeforeEach
  void setUp() {
    LlmConfig.ApiConfig api = new LlmConfig.ApiConfig();
    api.setBaseUrl("http://llm.test/v1");
    api.setApiKey("test-key");
    api.setModel("test-model");
    api.setTemperature(0.7);
    api.setMaxTokens(2000);
    api.setToolCalling("auto");

    config = new LlmConfig();
    config.setApi(api);

    restTemplate = new RestTemplate();
    RestTemplate healthRestTemplate = new RestTemplate();
    server = MockRestServiceServer.createServer(restTemplate);
    healthServer = MockRestServiceServer.bindTo(healthRestTemplate).ignoreExpectOrder(true).build();
    // Every generation call runs the reachability probe first.
    healthServer
        .expect(ExpectedCount.manyTimes(), requestTo(MODELS_URL))
        .andRespond(withSuccess("{\"data\":[]}", MediaType.APPLICATION_JSON));
    // The context-length probe, in the background: this server names no limit.
    healthServer
        .expect(ExpectedCount.manyTimes(), requestTo(COMPLETIONS_URL))
        .andRespond(withStatus(HttpStatus.NOT_FOUND));

    client = new LlmClient(config, settingsFrom(config), restTemplate, healthRestTemplate);
  }

  /** The deployment's values, as Settings reads them when nothing is changed in the app. */
  static com.tracepcap.common.settings.LlmSettings settingsFrom(LlmConfig config) {
    LlmConfig.ApiConfig a = config.getApi();
    return new com.tracepcap.common.settings.LlmSettings(null) {
      @Override public String baseUrl() { return a.getBaseUrl(); }
      @Override public String apiKey() { return a.getApiKey(); }
      @Override public String model() { return a.getModel(); }
      @Override public double temperature() { return a.getTemperature(); }
      @Override public int maxTokens() { return a.getMaxTokens(); }
      @Override public int timeoutSeconds() { return a.getTimeoutSeconds() == null ? 300 : a.getTimeoutSeconds(); }
      @Override public String toolCalling() { return a.getToolCalling() == null ? "auto" : a.getToolCalling(); }
    };
  }

  private static String messageResponse(String content) {
    return """
        {"choices":[{"message":{"role":"assistant","content":"%s"}}]}
        """
        .formatted(content);
  }

  private static String toolCallResponse(String name, String argumentsJson) {
    // arguments is a JSON *string* on the wire, so the inner braces arrive escaped
    String escaped = argumentsJson.replace("\"", "\\\"");
    return """
        {"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[
          {"id":"call_1","type":"function","function":{"name":"%s","arguments":"%s"}}
        ]}}]}
        """
        .formatted(name, escaped);
  }

  private static LlmToolSpec tool() {
    return new LlmToolSpec(
        "query_conversations",
        "search conversations",
        LlmToolSpec.schema().property("srcIp", "string", "source ip").build());
  }

  @Test
  void plainCompletionSendsNoToolFields() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(method(HttpMethod.POST))
        .andExpect(jsonPath("$.model").value("test-model"))
        .andExpect(jsonPath("$.max_tokens").value(2000))
        .andExpect(
            content()
                .string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("tools"))))
        .andRespond(withSuccess(messageResponse("hello"), MediaType.APPLICATION_JSON));

    assertThat(client.generateCompletion("sys", "user")).isEqualTo("hello");
    server.verify();
  }

  @Test
  void parsesToolCallArgumentsAsSchemaConstrained() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tools[0].function.name").value("query_conversations"))
        .andExpect(jsonPath("$.tools[0].type").value("function"))
        .andExpect(jsonPath("$.tool_choice").value("required"))
        .andRespond(
            withSuccess(
                toolCallResponse("query_conversations", "{\"srcIp\":\"10.0.0.5\"}"),
                MediaType.APPLICATION_JSON));

    LlmToolResponse response = client.generateWithTools("sys", "user", List.of(tool()));

    assertThat(response.schemaConstrained()).isTrue();
    assertThat(response.callsTo("query_conversations"))
        .singleElement()
        .satisfies(call -> assertThat(call.argumentsJson()).isEqualTo("{\"srcIp\":\"10.0.0.5\"}"));
    server.verify();
  }

  @Test
  void fallsBackToFreeTextWhenServerRejectsTools() {
    // tool_choice=required rejected → retried with auto → also rejected → tools dropped entirely
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tool_choice").value("required"))
        .andRespond(
            withStatus(HttpStatus.BAD_REQUEST).body("{\"error\":\"tools are not supported\"}"));
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tool_choice").value("auto"))
        .andRespond(
            withStatus(HttpStatus.BAD_REQUEST).body("{\"error\":\"tools are not supported\"}"));
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tools").doesNotExist())
        .andRespond(withSuccess(messageResponse("{ }"), MediaType.APPLICATION_JSON));

    LlmToolResponse response = client.generateWithTools("sys", "user", List.of(tool()));

    assertThat(response.schemaConstrained()).isFalse();
    assertThat(response.content()).isEqualTo("{ }");
    server.verify();
  }

  @Test
  void retriesWithToolChoiceAutoWhenOnlyForcingIsRejected() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tool_choice").value("required"))
        .andRespond(
            withStatus(HttpStatus.BAD_REQUEST)
                .body("{\"error\":\"tool_choice is not supported\"}"));
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tool_choice").value("auto"))
        .andExpect(jsonPath("$.tools[0].function.name").value("query_conversations"))
        .andRespond(
            withSuccess(
                toolCallResponse("query_conversations", "{\"dstPort\":4444}"),
                MediaType.APPLICATION_JSON));

    LlmToolResponse response = client.generateWithTools("sys", "user", List.of(tool()));

    assertThat(response.schemaConstrained()).isTrue();
    server.verify();
  }

  @Test
  void remembersThatServerIgnoresToolsAndStopsOfferingThem() {
    // Accepts the request, answers with prose anyway: the tool declaration went nowhere.
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tools").exists())
        .andRespond(
            withSuccess(messageResponse("{\\\"queries\\\":[]}"), MediaType.APPLICATION_JSON));
    // Second call must not pay for the same discovery again.
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tools").doesNotExist())
        .andRespond(withSuccess(messageResponse("second"), MediaType.APPLICATION_JSON));

    LlmToolResponse first = client.generateWithTools("sys", "user", List.of(tool()));
    assertThat(first.schemaConstrained()).isFalse();
    assertThat(first.content()).isEqualTo("{\"queries\":[]}");

    LlmToolResponse second = client.generateWithTools("sys", "user", List.of(tool()));
    assertThat(second.schemaConstrained()).isFalse();
    assertThat(second.content()).isEqualTo("second");
    server.verify();
  }

  @Test
  void toolCallingOffNeverOffersTools() {
    config.getApi().setToolCalling("off");
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tools").doesNotExist())
        .andRespond(withSuccess(messageResponse("plain"), MediaType.APPLICATION_JSON));

    LlmToolResponse response = client.generateWithTools("sys", "user", List.of(tool()));

    assertThat(response.schemaConstrained()).isFalse();
    assertThat(response.content()).isEqualTo("plain");
    server.verify();
  }

  @Test
  void toolCallingOnKeepsOfferingToolsAfterTheServerIgnoresThem() {
    config.getApi().setToolCalling("on");
    server
        .expect(ExpectedCount.twice(), requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.tools").exists())
        .andRespond(withSuccess(messageResponse("prose"), MediaType.APPLICATION_JSON));

    client.generateWithTools("sys", "user", List.of(tool()));
    client.generateWithTools("sys", "user", List.of(tool()));

    server.verify();
  }

  @Test
  void classifiesContextLengthErrorsFromTheServer() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andRespond(
            withStatus(HttpStatus.BAD_REQUEST)
                .body(
                    "{\"error\":\"This model's maximum context length is 4096 tokens."
                        + " However, you requested 5200 (5000 in the messages)\"}"));

    assertThatThrownBy(() -> client.generateCompletion("sys", "user"))
        .isInstanceOf(ContextLengthExceededException.class);
    server.verify();
  }

  @Test
  void emptyChoicesIsAnLlmError() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andRespond(withSuccess("{\"choices\":[]}", MediaType.APPLICATION_JSON));

    assertThatThrownBy(() -> client.generateCompletion("sys", "user"))
        .isInstanceOf(LlmException.class)
        .hasFieldOrPropertyWithValue("errorCode", LlmException.ErrorCode.LLM_BAD_RESPONSE);
    server.verify();
  }

  @Test
  void blankContentIsAnLlmError() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andRespond(withSuccess(messageResponse("  "), MediaType.APPLICATION_JSON));

    assertThatThrownBy(() -> client.generateCompletion("sys", "user"))
        .isInstanceOf(LlmException.class)
        .hasFieldOrPropertyWithValue("errorCode", LlmException.ErrorCode.LLM_BAD_RESPONSE);
    server.verify();
  }

  @Test
  void blankReplyToToolsFallsBackToAPlainCompletion() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andRespond(withSuccess(messageResponse(""), MediaType.APPLICATION_JSON));
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andRespond(withSuccess(messageResponse("plain text"), MediaType.APPLICATION_JSON));

    LlmToolResponse response = client.generateWithTools("sys", "user", List.of(tool()));

    assertThat(response.schemaConstrained()).isFalse();
    assertThat(response.content()).isEqualTo("plain text");
    server.verify();
  }

  @Test
  void hittingTheTokenCapWithNoMessageIsReportedAsTruncated() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andRespond(
            withSuccess(
                "{\"choices\":[{\"finish_reason\":\"length\"}]}", MediaType.APPLICATION_JSON));

    assertThatThrownBy(() -> client.generateCompletion("sys", "user"))
        .isInstanceOf(LlmException.class)
        .hasFieldOrPropertyWithValue("errorCode", LlmException.ErrorCode.OUTPUT_TRUNCATED);
    server.verify();
  }

  /** A client whose LLM_MAX_TOKENS is this (0 = size each reply to the context). */
  private LlmClient withCeiling(int maxTokens) {
    config.getApi().setMaxTokens(maxTokens);
    RestTemplate health = new RestTemplate();
    MockRestServiceServer h = MockRestServiceServer.bindTo(health).ignoreExpectOrder(true).build();
    h.expect(ExpectedCount.manyTimes(), requestTo(MODELS_URL))
        .andRespond(withSuccess("{\"data\":[]}", MediaType.APPLICATION_JSON));
    h.expect(ExpectedCount.manyTimes(), requestTo(COMPLETIONS_URL))
        .andRespond(withStatus(HttpStatus.NOT_FOUND));
    return new LlmClient(config, settingsFrom(config), restTemplate, health);
  }

  @Test
  void withNoCeilingAndNoKnownContextTheFallbackIsAskedAndThenNoCap() {
    LlmClient auto = withCeiling(0);
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(LlmClient.FALLBACK_REPLY_TOKENS))
        .andRespond(
            withSuccess("{\"choices\":[{\"finish_reason\":\"length\"}]}", MediaType.APPLICATION_JSON));
    // Some servers default to a hundred tokens without max_tokens, so the guess came first.
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").doesNotExist())
        .andRespond(withSuccess(messageResponse("whole"), MediaType.APPLICATION_JSON));

    assertThat(auto.generateCompletion("sys", "user")).isEqualTo("whole");
    server.verify();
  }

  /** The request as sent is guessed at, not just the prompts: allow its JSON's few hundred chars. */
  private static org.hamcrest.Matcher<Integer> roomAfter(int context, int promptChars) {
    int most = context - promptChars / 2 - LlmClient.TEMPLATE_MARGIN;
    return org.hamcrest.Matchers.allOf(
        org.hamcrest.Matchers.lessThan(most), org.hamcrest.Matchers.greaterThan(most - 200));
  }

  @Test
  void withNoCeilingTheReplyGetsWhatTheContextLeaves() {
    LlmClient auto = withCeiling(0);
    auto.assumeLimits(32_768, null);
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(roomAfter(32_768, 7)))
        .andRespond(withSuccess(messageResponse("hello"), MediaType.APPLICATION_JSON));

    auto.generateCompletion("sys", "user");
    server.verify();
  }

  @Test
  void aCeilingCapsTheReplyAndSoDoesTheServersOwnCap() {
    client.assumeLimits(32_768, null);
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(2000))
        .andRespond(withSuccess(messageResponse("hello"), MediaType.APPLICATION_JSON));
    client.generateCompletion("sys", "user");
    server.verify();

    server.reset();
    LlmClient auto = withCeiling(0);
    auto.assumeLimits(262_144, 16_384);
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(16_384))
        .andRespond(withSuccess(messageResponse("hello"), MediaType.APPLICATION_JSON));
    auto.generateCompletion("sys", "user");
    server.verify();
  }

  @Test
  void aReplyCutOffShortOfTheRealRoomIsAskedAgainWithIt() {
    LlmClient auto = withCeiling(0);
    auto.assumeLimits(10_000, null);
    String prompt = "x".repeat(7_997); // with "sys": 8000 chars, guessed at over 4000 tokens
    int counted = 10_000 - 2_000 - LlmClient.TEMPLATE_MARGIN;
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(roomAfter(10_000, 8_000)))
        .andRespond(
            withSuccess(
                "{\"choices\":[{\"finish_reason\":\"length\",\"message\":{\"role\":\"assistant\",\"content\":\"{\\\"cut\"}}],"
                    + "\"usage\":{\"prompt_tokens\":2000}}",
                MediaType.APPLICATION_JSON));
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(counted))
        .andRespond(withSuccess(messageResponse("whole"), MediaType.APPLICATION_JSON));

    assertThat(auto.generateCompletion("sys", prompt)).isEqualTo("whole");
    server.verify();
  }

  @Test
  void aReplyCutOffAtTheCeilingSaysToRaiseIt() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andRespond(
            withSuccess(
                "{\"choices\":[{\"finish_reason\":\"length\"}],\"usage\":{\"prompt_tokens\":3}}",
                MediaType.APPLICATION_JSON));

    assertThatThrownBy(() -> client.generateCompletion("sys", "user"))
        .isInstanceOf(LlmException.class)
        .hasMessageContaining("(2000 tokens)")
        .hasMessageContaining("Raise LLM_MAX_TOKENS, or set it to 0");
    server.verify();
  }

  @Test
  void aBudgetTheServerRefusesByNamingItsLimitIsAskedAgainWithinIt() {
    LlmClient high = withCeiling(300_000);
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(300_000))
        .andRespond(
            withStatus(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(
                    "{\"error\":{\"message\":\"max_tokens=300000 cannot be greater than"
                        + " max_model_len=max_total_tokens=262144.\"}}"));
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(roomAfter(262_144, 7)))
        .andRespond(withSuccess(messageResponse("hello"), MediaType.APPLICATION_JSON));

    assertThat(high.generateCompletion("sys", "user")).isEqualTo("hello");
    assertThat(high.getModelContextLength()).isEqualTo(262_144);
    server.verify();
  }

  @Test
  void anOvershootOfAKnownContextIsAskedAgainFromTheServersPromptCount() {
    LlmClient auto = withCeiling(0);
    auto.assumeLimits(32_768, null);
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andRespond(
            withStatus(HttpStatus.BAD_REQUEST)
                .body(
                    "{\"error\":\"This model's maximum context length is 32768 tokens. However, you"
                        + " requested 34300 tokens (2300 in the messages, 32000 in the completion)\"}"));
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(32_768 - 2_300 - LlmClient.TEMPLATE_MARGIN))
        .andRespond(withSuccess(messageResponse("hello"), MediaType.APPLICATION_JSON));

    assertThat(auto.generateCompletion("sys", "user")).isEqualTo("hello");
    server.verify();
  }

  @Test
  void aConfiguredContextLengthIsNotReplacedByOneAnErrorNames() {
    config.getApi().setContextLength(16_384);
    LlmClient pinned = withCeiling(300_000);
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(roomAfter(16_384, 7)))
        .andRespond(
            withStatus(HttpStatus.BAD_REQUEST)
                .body("{\"error\":\"max_tokens cannot be greater than max_model_len=131072\"}"));

    assertThatThrownBy(() -> pinned.generateCompletion("sys", "user"))
        .isInstanceOf(ContextLengthExceededException.class);
    assertThat(pinned.getModelContextLength()).isEqualTo(16_384);
    server.verify();
  }

  @Test
  void onlyServersThatRefuseBeforeGeneratingAreProbed() {
    assertThat(LlmClient.namesItsLimit("gpustack")).isTrue();
    assertThat(LlmClient.namesItsLimit("vllm")).isTrue();
    assertThat(LlmClient.namesItsLimit("sglang")).isTrue();
    assertThat(LlmClient.namesItsLimit("organization_owner")).isFalse(); // LM Studio
    assertThat(LlmClient.namesItsLimit("library")).isFalse(); // Ollama
    assertThat(LlmClient.namesItsLimit(null)).isFalse();
  }

  @Test
  void theProbeReadsTheLimitTheServerNames() {
    RestTemplate health = new RestTemplate();
    MockRestServiceServer h = MockRestServiceServer.createServer(health);
    h.expect(requestTo(COMPLETIONS_URL))
        .andExpect(jsonPath("$.max_tokens").value(LlmClient.PROBE_MAX_TOKENS))
        .andRespond(
            withStatus(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(
                    "{\"error\":{\"message\":\"max_tokens=100000000 cannot be greater than"
                        + " max_model_len=max_total_tokens=262144.\"}}"));
    LlmClient probing = new LlmClient(config, settingsFrom(config), restTemplate, health);

    assertThat(probing.probeContextLength(null)).isEqualTo(262_144);
    h.verify();
  }

  @Test
  void readsTheContextLengthFromEachServersWording() {
    assertThat(LlmClient.contextLengthIn("cannot be greater than max_model_len=max_total_tokens=262144"))
        .isEqualTo(262_144);
    assertThat(LlmClient.contextLengthIn("max_model_len=8192")).isEqualTo(8192);
    assertThat(LlmClient.contextLengthIn("This model's maximum context length is 4096 tokens"))
        .isEqualTo(4096);
    assertThat(LlmClient.contextLengthIn("{\"type\":\"exceed_context_size_error\",\"n_prompt_tokens\":9000,\"n_ctx\":8192}"))
        .isEqualTo(8192);
    assertThat(LlmClient.contextLengthIn("nothing here")).isZero();
  }

  @Test
  void rejectedCompletionIsNotAnOutage() {
    server
        .expect(requestTo(COMPLETIONS_URL))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED));

    assertThatThrownBy(() -> client.generateCompletion("sys", "user"))
        .isInstanceOf(LlmException.class)
        .hasFieldOrPropertyWithValue("errorCode", LlmException.ErrorCode.LLM_BAD_RESPONSE);
    server.verify();
  }

  @Test
  void rejectedHealthCheckIsNotAnOutage() {
    RestTemplate healthRestTemplate = new RestTemplate();
    MockRestServiceServer rejectingHealthServer =
        MockRestServiceServer.createServer(healthRestTemplate);
    // The model-capability check lists models on the same short-timeout client, so expect it too.
    rejectingHealthServer
        .expect(ExpectedCount.manyTimes(), requestTo(MODELS_URL))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED));
    LlmClient rejectedClient = new LlmClient(config, settingsFrom(config), restTemplate, healthRestTemplate);

    assertThatThrownBy(() -> rejectedClient.generateCompletion("sys", "user"))
        .isInstanceOf(LlmException.class)
        .hasFieldOrPropertyWithValue("errorCode", LlmException.ErrorCode.LLM_BAD_RESPONSE);
  }
}
