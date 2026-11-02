package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.common.exception.LlmException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/** A story the model garbled must reach the user as an LLM failure, not an unexpected error. */
class StoryServiceLlmOutputTest {

  private final StoryService service =
      new StoryService(
          null, null, null, null, null, null, new ObjectMapper(), null, null, null, null, null,
          null, null, null, null);

  private void parse(String content) {
    ReflectionTestUtils.invokeMethod(
        service, "parseStoryContent", content, UUID.randomUUID(), UUID.randomUUID());
  }

  @Test
  void unreadableStoryIsAnLlmFailure() {
    assertThatThrownBy(() -> parse("this is not a story"))
        .isInstanceOf(LlmException.class)
        .hasFieldOrPropertyWithValue("errorCode", LlmException.ErrorCode.LLM_BAD_RESPONSE)
        .hasMessageContaining("could not be read");
  }

  @Test
  void blankStoryIsAnLlmFailure() {
    assertThatThrownBy(() -> parse("   "))
        .isInstanceOf(LlmException.class)
        .hasFieldOrPropertyWithValue("errorCode", LlmException.ErrorCode.LLM_BAD_RESPONSE);
  }
}
