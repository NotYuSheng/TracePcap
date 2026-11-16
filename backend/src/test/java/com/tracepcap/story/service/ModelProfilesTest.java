package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.common.settings.LlmSettings;
import com.tracepcap.common.settings.PolicyEditGate;
import org.junit.jupiter.api.Test;

/** Telling model kinds apart and failing clearly on the wrong kind (#1165). */
class ModelProfilesTest {

  @Test
  void sameModelToleratesTheServersOwnNaming() {
    assertThat(ModelProfiles.sameModel("qwen3-4b-2507", "qwen/qwen3-4b-2507")).isTrue();
    assertThat(ModelProfiles.sameModel("qwen3-4b-2507", "qwen3-4b-2507.gguf")).isTrue();
    assertThat(ModelProfiles.sameModel("text-embedding-nomic-embed-text-v1.5", "huihui-qwen3.8-flash-next-abliterated")).isFalse();
    assertThat(ModelProfiles.sameModel("x", null)).isTrue();
  }

  @Test
  void embeddingModelsAreKnownByName_whenTheServerDoesntSay() {
    assertThat(ModelProfiles.fromName("text-embedding-nomic-embed-text-v1.5").canChat()).isFalse();
    assertThat(ModelProfiles.fromName("BAAI/bge-small-en").canChat()).isFalse();
    assertThat(ModelProfiles.fromName("qwen/qwen3-4b-2507").canChat()).isTrue();
  }

  @Test
  void thinkingIsNotTheAnswer() {
    assertThat(LlmClient.stripThinking("<think>maybe {\"a\":1}?</think>{\"answer\":\"x\"}")).isEqualTo("{\"answer\":\"x\"}");
    assertThat(LlmClient.stripThinking("Sure. <think>still going")).isEqualTo("Sure.");
    assertThat(LlmClient.stripThinking("<think>only thinking")).isEmpty();
    assertThat(LlmClient.stripThinking("plain")).isEqualTo("plain");
  }

  private final LlmConnectionTester tester =
      new LlmConnectionTester(mock(LlmSettings.class), mock(PolicyEditGate.class), new ObjectMapper());

  @Test
  void aReplyFromAnotherModelIsAWarning() {
    var step = tester.replyStep("text-embedding-nomic", "{\"model\":\"huihui-qwen3.8\",\"choices\":[{\"message\":{\"content\":\"OK\"}}]}", 20);
    assertThat(step.getStatus()).isEqualTo("WARN");
    assertThat(step.getDetail()).contains("but as huihui-qwen3.8").contains("Load text-embedding-nomic");
  }

  @Test
  void aReasoningModelIsNamedAsOne() {
    var step = tester.replyStep("deepseek-r1", "{\"model\":\"deepseek-r1\",\"choices\":[{\"message\":{\"content\":\"\",\"reasoning_content\":\"Hmm\"}}]}", 20);
    assertThat(step.getStatus()).isEqualTo("OK");
    assertThat(step.getDetail()).contains("reasoning model").contains("LLM_MAX_TOKENS");
  }
}
