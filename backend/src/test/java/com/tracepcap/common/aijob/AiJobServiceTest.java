package com.tracepcap.common.aijob;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.common.exception.ContextLengthExceededException;
import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.common.exception.LlmException;
import com.tracepcap.config.security.CurrentActor;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AiJobServiceTest {

  /** Runs queued work only when told to, so each state can be looked at. */
  static class StepExecutor extends AbstractExecutorService {
    final Deque<Runnable> queued = new ArrayDeque<>();
    @Override public void execute(Runnable r) { queued.add(r); }
    void runNext() { queued.removeFirst().run(); }
    @Override public void shutdown() {}
    @Override public List<Runnable> shutdownNow() { return List.of(); }
    @Override public boolean isShutdown() { return false; }
    @Override public boolean isTerminated() { return false; }
    @Override public boolean awaitTermination(long t, TimeUnit u) { return true; }
  }

  /** A clock the test moves forward. */
  static class TestClock extends Clock {
    Instant now = Instant.parse("2026-11-17T10:00:00Z");
    @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(java.time.ZoneId z) { return this; }
    @Override public Instant instant() { return now; }
    void advance(Duration d) { now = now.plus(d); }
  }

  final CurrentActor actor = mock(CurrentActor.class);
  final StepExecutor worker = new StepExecutor();
  final TestClock clock = new TestClock();
  AiJobService jobs;
  final UUID capture = UUID.randomUUID();
  final UUID network = UUID.randomUUID();

  @BeforeEach
  void setUp() {
    when(actor.username()).thenReturn("system");
    jobs = new AiJobService(actor, clock, worker);
  }

  @Test
  void a_job_waits_runs_and_ends_with_its_result() {
    AiJobDto queued = jobs.submit("STORY", capture, "strrat.pcapng", () -> "the story");
    assertThat(queued.getStatus()).isEqualTo("WAITING");
    assertThat(queued.getPosition()).isEqualTo(1);
    assertThat(queued.getTrigger()).isEqualTo("USER");

    clock.advance(Duration.ofMinutes(7));
    worker.runNext();

    AiJobDto done = jobs.get(queued.getId());
    assertThat(done.getStatus()).isEqualTo("DONE");
    assertThat(done.getResult()).isEqualTo("the story");
    assertThat(done.getPosition()).isNull();
    assertThat(done.getFinishedAt()).isNotNull();
  }

  @Test
  void asking_again_while_one_waits_returns_that_job() {
    AiJobDto first = jobs.submit("STORY", capture, "strrat.pcapng", () -> "a");
    AiJobDto again = jobs.submit("STORY", capture, "strrat.pcapng", () -> "b");
    AiJobDto other = jobs.submit("INSIGHTS", network, "Office Audit", () -> "c");

    assertThat(again.getId()).isEqualTo(first.getId());
    assertThat(other.getId()).isNotEqualTo(first.getId());
    assertThat(worker.queued).hasSize(2);
  }

  @Test
  void jobs_wait_in_line_in_the_order_they_were_asked_for() {
    jobs.submit("STORY", capture, "strrat.pcapng", "UPLOAD", () -> "a");
    clock.advance(Duration.ofSeconds(1));
    AiJobDto second = jobs.submit("INSIGHTS", network, "Office Audit", () -> "b");
    assertThat(second.getPosition()).isEqualTo(2);

    worker.runNext();
    assertThat(jobs.get(second.getId()).getPosition()).isEqualTo(1);
    assertThat(jobs.list(null, null)).extracting(AiJobDto::getKind).containsExactly("INSIGHTS", "STORY");
  }

  @Test
  void a_waiting_job_can_be_cancelled_and_then_never_runs() {
    boolean[] ran = {false};
    AiJobDto job = jobs.submit("STORY", capture, "strrat.pcapng", () -> { ran[0] = true; return "x"; });

    assertThat(jobs.cancel(job.getId()).getStatus()).isEqualTo("CANCELLED");
    worker.runNext();

    assertThat(ran[0]).isFalse();
    assertThat(jobs.get(job.getId()).getStatus()).isEqualTo("CANCELLED");
  }

  @Test
  void a_running_job_cannot_be_cancelled() {
    AiJobDto[] seen = new AiJobDto[1];
    UUID[] id = new UUID[1];
    id[0] = jobs.submit("STORY", capture, "strrat.pcapng", () -> {
      assertThatThrownBy(() -> jobs.cancel(id[0])).isInstanceOf(IllegalArgumentException.class);
      seen[0] = jobs.get(id[0]);
      return "x";
    }).getId();
    worker.runNext();
    assertThat(seen[0].getStatus()).isEqualTo("RUNNING");
  }

  @Test
  void only_whoever_asked_or_an_admin_can_cancel() {
    when(actor.username()).thenReturn("alice");
    AiJobDto job = jobs.submit("STORY", capture, "strrat.pcapng", () -> "x");

    when(actor.username()).thenReturn("bob");
    assertThatThrownBy(() -> jobs.cancel(job.getId())).isInstanceOf(ForbiddenException.class);

    when(actor.isAdmin()).thenReturn(true);
    assertThat(jobs.cancel(job.getId()).getStatus()).isEqualTo("CANCELLED");
  }

  @Test
  void a_prompt_too_big_fails_with_the_prompt_to_cut_down() {
    AiJobDto job = jobs.submit("STORY", capture, "strrat.pcapng", () -> {
      throw new ContextLengthExceededException(40000, 32768, "the prompt");
    });
    worker.runNext();

    AiJobDto failed = jobs.get(job.getId());
    assertThat(failed.getStatus()).isEqualTo("FAILED");
    assertThat(failed.getError().getErrorCode()).isEqualTo("CONTEXT_LENGTH_EXCEEDED");
    assertThat(failed.getError().getPromptText()).isEqualTo("the prompt");
    assertThat(failed.getError().getContextLength()).isEqualTo(32768);
    // The list leaves the prompt out.
    assertThat(jobs.list(null, null).get(0).getError().getPromptText()).isNull();
  }

  @Test
  void an_llm_error_keeps_its_code() {
    AiJobDto job = jobs.submit("INSIGHTS", network, "Office Audit", () -> {
      throw new LlmException("timed out", null, LlmException.ErrorCode.LLM_TIMEOUT);
    });
    worker.runNext();
    assertThat(jobs.get(job.getId()).getError().getErrorCode()).isEqualTo("LLM_TIMEOUT");
  }

  @Test
  void the_typical_time_is_the_median_of_the_last_runs() {
    assertThat(jobs.submit("STORY", UUID.randomUUID(), "a", () -> "x").getTypicalMs()).isNull();
    worker.runNext(); // finishes at once: 0 min
    for (int minutes : new int[] {7, 3, 9}) {
      jobs.submit("STORY", UUID.randomUUID(), "a", () -> {
        clock.advance(Duration.ofMinutes(minutes));
        return "x";
      });
      worker.runNext();
    }
    // 0, 7, 3 and 9 minutes: the median (upper middle) is 7.
    assertThat(jobs.submit("STORY", capture, "a", () -> "x").getTypicalMs())
        .isEqualTo(Duration.ofMinutes(7).toMillis());
  }

  @Test
  void finished_jobs_are_kept_for_thirty_minutes() {
    AiJobDto job = jobs.submit("STORY", capture, "a", () -> "x");
    worker.runNext();
    clock.advance(Duration.ofMinutes(29));
    assertThat(jobs.list(null, null)).hasSize(1);
    clock.advance(Duration.ofMinutes(2));
    assertThat(jobs.list(null, null)).isEmpty();
    assertThatThrownBy(() -> jobs.get(job.getId()))
        .isInstanceOf(com.tracepcap.common.exception.ResourceNotFoundException.class);
  }

  @Test
  void the_list_filters_by_kind_and_subject() {
    jobs.submit("STORY", capture, "a", () -> "x");
    jobs.submit("INSIGHTS", network, "b", () -> "y");
    assertThat(jobs.list("STORY", null)).hasSize(1);
    assertThat(jobs.list(null, network)).extracting(AiJobDto::getKind).containsExactly("INSIGHTS");
  }

  @Test
  void jobs_about_different_hosts_on_one_capture_are_separate() {
    AiJobDto a = jobs.submitFor("ROLE_SUGGESTION", capture, "IP:10.0.0.5", "10.0.0.5", () -> "a");
    AiJobDto again = jobs.submitFor("ROLE_SUGGESTION", capture, "IP:10.0.0.5", "10.0.0.5", () -> "a2");
    AiJobDto b = jobs.submitFor("ROLE_SUGGESTION", capture, "IP:10.0.0.6", "10.0.0.6", () -> "b");

    assertThat(again.getId()).isEqualTo(a.getId());
    assertThat(b.getId()).isNotEqualTo(a.getId());
    assertThat(jobs.list("ROLE_SUGGESTION", capture, "IP:10.0.0.6")).extracting(AiJobDto::getId).containsExactly(b.getId());
    assertThat(a.getSubjectKey()).isEqualTo("IP:10.0.0.5");
  }

  @Test
  void a_job_with_no_subject_is_told_apart_by_its_key() {
    AiJobDto a = jobs.submitFor("TRACE_EXPLANATIONS", null, "conv-1", "10.0.0.5:443 → 1.2.3.4:51000", () -> "x");
    AiJobDto b = jobs.submitFor("TRACE_EXPLANATIONS", null, "conv-2", "other", () -> "y");
    assertThat(b.getId()).isNotEqualTo(a.getId());
    assertThat(jobs.submitFor("TRACE_EXPLANATIONS", null, "conv-1", "again", () -> "z").getId()).isEqualTo(a.getId());
  }

  @Test
  void an_answer_that_needs_no_model_time_is_done_at_once_and_never_queued() {
    jobs.submit("STORY", capture, "a", () -> "story"); // the model is busy
    AiJobDto cached = jobs.finished("TRACE_EXPLANATIONS", null, "conv-1", "conv", "cached explanations");

    assertThat(cached.getStatus()).isEqualTo("DONE");
    assertThat(cached.getResult()).isEqualTo("cached explanations");
    assertThat(worker.queued).hasSize(1);
  }
}
