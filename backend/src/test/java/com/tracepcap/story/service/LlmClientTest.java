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
    healthServer = MockRestServiceServer.createServer(healthRestTemplate);
    // Every generation call runs the reachability probe first.
    healthServer
        .expect(ExpectedCount.manyTimes(), requestTo(MODELS_URL))
        .andRespond(withSuccess("{\"data\":[]}", MediaType.APPLICATION_JSON));

    client = new LlmClient(config, restTemplate, healthRestTemplate);
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
        .isInstanceOf(LlmException.class);
    server.verify();
  }
}
