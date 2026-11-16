package com.tracepcap.story.chat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.common.exception.LlmException;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.story.chat.dto.ChatTurnDto;
import com.tracepcap.story.chat.dto.ChatTurnRequest;
import com.tracepcap.story.service.LlmClient;
import com.tracepcap.story.service.LlmClient.CallRequest;
import com.tracepcap.story.service.LlmClient.Reply;
import com.tracepcap.story.service.LlmToolSpec;
import com.tracepcap.story.service.StoryService;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** The capture chat's loop (#1161): tools run, results go back, the answer comes out. */
class CaptureChatServiceTest {

  private static final UUID FILE = UUID.randomUUID();

  /** A stand-in for check_filter: valid unless the filter says "bad". */
  static class FakeFilterTool implements ChatTool {
    final AtomicReference<String> seen = new AtomicReference<>();
    public String name() { return "check_filter"; }
    public String label() { return "Check a filter"; }
    public String summary() { return "checks"; }
    public String example() { return "x"; }
    public LlmToolSpec spec() { return new LlmToolSpec(name(), "check", LlmToolSpec.schema().property("filter", "string", "f").build()); }
    public Result run(ChatToolContext ctx, JsonNode args) {
      seen.set(args.path("filter").asText());
      if (args.path("filter").asText().contains("bad")) throw new IllegalArgumentException("not a filter");
      return new Result("valid · 50 packets match", Map.of("valid", true, "matchingPackets", 50),
          new CheckedFilter(args.path("filter").asText(), true, 50, null));
    }
  }

  private CaptureChatService service(LlmClient llm, ChatTool... tools) {
    StoryService stories = mock(StoryService.class);
    when(stories.knowledgeContext(any())).thenReturn("## Confirmed findings\n- beacon\n");
    when(stories.storyContent(any())).thenReturn(Optional.empty());
    FileRepository files = mock(FileRepository.class);
    when(files.existsById(FILE)).thenReturn(true);
    return new CaptureChatService(llm, new ChatToolRegistry(List.of(tools)), stories, files, new ObjectMapper());
  }

  private static ChatTurnRequest ask(String q) {
    ChatTurnRequest r = new ChatTurnRequest();
    r.setQuestion(q);
    return r;
  }

  private static ChatTurnDto await(CaptureChatService s, ChatTurnDto t) throws InterruptedException {
    for (int i = 0; i < 200; i++) {
      ChatTurnDto now = s.get(FILE, t.getId());
      if (!"RUNNING".equals(now.getStatus())) return now;
      Thread.sleep(20);
    }
    throw new AssertionError("turn never finished");
  }

  @Test
  void runsTheToolsTheModelAsksFor_thenAnswers() throws Exception {
    LlmClient llm = mock(LlmClient.class);
    FakeFilterTool tool = new FakeFilterTool();
    when(llm.converse(anyList(), anyList()))
        .thenReturn(new Reply(null, List.of(new CallRequest("c1", "check_filter", "{\"filter\":\"udp.port == 53\"}")), true))
        .thenReturn(new Reply("<think>done</think>{\"answer\":\"Use udp.port == 53.\",\"followUpQuestions\":[\"a\",\"b\",\"c\",\"d\"]}", List.of(), true));

    var s = service(llm, tool);
    ChatTurnDto done = await(s, s.start(FILE, ask("A filter for DNS?")));

    assertThat(done.getStatus()).isEqualTo("DONE");
    assertThat(done.getAnswer()).isEqualTo("Use udp.port == 53.");
    assertThat(done.getFollowUpQuestions()).containsExactly("a", "b", "c");
    assertThat(done.getSteps()).singleElement().satisfies(st -> {
      assertThat(st.getLabel()).isEqualTo("Check a filter");
      assertThat(st.getStatus()).isEqualTo("DONE");
      assertThat(st.getSummary()).isEqualTo("valid · 50 packets match");
    });
    assertThat(done.getFilters()).extracting(ChatTurnDto.FilterDto::getExpression).containsExactly("udp.port == 53");
    assertThat(done.isToolsOffered()).isTrue();
    assertThat(tool.seen.get()).isEqualTo("udp.port == 53");
  }

  @Test
  void aToolErrorGoesBackToTheModel_andAnUnknownToolIsAFailedStep() throws Exception {
    LlmClient llm = mock(LlmClient.class);
    when(llm.converse(anyList(), anyList()))
        .thenReturn(new Reply(null, List.of(
            new CallRequest("c1", "check_filter", "{\"filter\":\"bad ==\"}"),
            new CallRequest("c2", "rm_rf", "{}")), true))
        .thenReturn(new Reply("{\"answer\":\"No valid filter.\"}", List.of(), true));

    var s = service(llm, new FakeFilterTool());
    ChatTurnDto done = await(s, s.start(FILE, ask("filter?")));

    assertThat(done.getSteps()).extracting(ChatTurnDto.ChatStepDto::getStatus).containsExactly("FAILED", "FAILED");
    assertThat(done.getFilters()).isEmpty();
    assertThat(done.getAnswer()).isEqualTo("No valid filter.");
  }

  @Test
  void stopsCallingToolsAfterTheLimit_andAsksForTheAnswer() throws Exception {
    LlmClient llm = mock(LlmClient.class);
    var loop = new Reply(null, List.of(new CallRequest("c", "check_filter", "{\"filter\":\"tcp\"}")), true);
    when(llm.converse(anyList(), anyList())).thenAnswer(inv -> {
      List<?> tools = inv.getArgument(1);
      return tools.isEmpty() ? new Reply("{\"answer\":\"Enough.\"}", List.of(), true) : loop;
    });

    var s = service(llm, new FakeFilterTool());
    ChatTurnDto done = await(s, s.start(FILE, ask("loop")));

    assertThat(done.getStatus()).isEqualTo("DONE");
    assertThat(done.getAnswer()).isEqualTo("Enough.");
    assertThat(done.getSteps().size()).isLessThanOrEqualTo(CaptureChatService.MAX_CALLS);
  }

  @Test
  void anLlmFailureEndsTheTurnWithItsCode() throws Exception {
    LlmClient llm = mock(LlmClient.class);
    when(llm.converse(anyList(), anyList()))
        .thenThrow(new LlmException("Failed to reach the LLM service", null, LlmException.ErrorCode.LLM_UNREACHABLE));
    var s = service(llm, new FakeFilterTool());
    ChatTurnDto done = await(s, s.start(FILE, ask("hi")));
    assertThat(done.getStatus()).isEqualTo("FAILED");
    assertThat(done.getErrorCode()).isEqualTo("LLM_UNREACHABLE");
  }

  @Test
  void plainTextIsTakenAsTheAnswerWhenTheModelSkipsTheJson() {
    var s = service(mock(LlmClient.class), new FakeFilterTool());
    assertThat(s.parse("```\nJust text.\n```").answer()).isEqualTo("Just text.");
    assertThat(s.parse("Sure! {\"answer\":\"Wrapped.\"} hope that helps").answer()).isEqualTo("Wrapped.");
  }
}
