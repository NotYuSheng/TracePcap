package com.tracepcap.common.aijob;

import com.tracepcap.common.exception.ContextLengthExceededException;
import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.common.exception.LlmException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.security.CurrentActor;
import jakarta.annotation.PreDestroy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * AI work that takes the model minutes (a story, a network's insights) runs here, in the
 * background, one job at a time: a local server answers one request at a time, so sending it
 * several only makes each slower. A job is created at once and checked on; it outlives the page
 * that asked for it, and asking again for the same thing while it waits returns that job.
 *
 * <p>The capture chat isn't queued here: a question someone is waiting on goes straight to the
 * model. Jobs live in memory and are kept for {@link #KEEP} once finished; a restart drops them.
 */
@Slf4j
@Service
public class AiJobService {

  static final Duration KEEP = Duration.ofMinutes(30);
  /** How many finished runs of a kind its typical time is taken from. */
  private static final int TYPICAL_OF = 5;

  private final CurrentActor actor;
  private final Clock clock;
  private final ExecutorService worker;
  private final Map<UUID, Job> jobs = new ConcurrentHashMap<>();
  private final Map<String, Deque<Long>> recentMs = new ConcurrentHashMap<>();

  @Autowired
  public AiJobService(CurrentActor actor) {
    this(actor, Clock.systemUTC(), Executors.newSingleThreadExecutor(r -> {
      Thread t = new Thread(r, "ai-job");
      t.setDaemon(true);
      return t;
    }));
  }

  AiJobService(CurrentActor actor, Clock clock, ExecutorService worker) {
    this.actor = actor;
    this.clock = clock;
    this.worker = worker;
  }

  @PreDestroy
  void stop() {
    worker.shutdownNow();
  }

  /** Someone asked for it. */
  public AiJobDto submit(String kind, UUID subjectId, String subjectName, Callable<?> work) {
    return submit(kind, subjectId, subjectName, "USER", work);
  }

  /**
   * Queues the work, or returns the job already waiting or running for the same kind and subject.
   * {@code trigger} is {@code USER} or {@code UPLOAD}.
   */
  public synchronized AiJobDto submit(
      String kind, UUID subjectId, String subjectName, String trigger, Callable<?> work) {
    evictOld();
    for (Job j : jobs.values()) {
      if (j.active() && j.kind.equals(kind) && j.subjectId.equals(subjectId)) return toDto(j, true);
    }
    Job job = new Job(UUID.randomUUID(), kind, subjectId, subjectName, trigger, actor.username(), now());
    jobs.put(job.id, job);
    job.future = worker.submit(() -> run(job, work));
    log.info("AI job {} queued: {} for {} ({})", job.id, kind, subjectId, trigger);
    return toDto(job, true);
  }

  public AiJobDto get(UUID id) {
    return toDto(find(id), true);
  }

  /** Waiting and running jobs, then the ones finished in the last 30 minutes, newest first. */
  public List<AiJobDto> list(String kind, UUID subjectId) {
    evictOld();
    return jobs.values().stream()
        .filter(j -> kind == null || j.kind.equals(kind))
        .filter(j -> subjectId == null || j.subjectId.equals(subjectId))
        .sorted(Comparator.comparing((Job j) -> !j.active()).thenComparing(j -> j.createdAt))
        .map(j -> toDto(j, false))
        .toList();
  }

  /**
   * Takes a waiting job out of line. A running one can't be stopped: the model is already
   * answering, and its answer is saved like any other.
   */
  public synchronized AiJobDto cancel(UUID id) {
    Job job = find(id);
    if (!actor.isAdmin() && !job.requestedBy.equals(actor.username())) {
      throw new ForbiddenException("Only whoever asked for this, or an admin, can cancel it.");
    }
    if (!"WAITING".equals(job.status)) {
      throw new IllegalArgumentException(
          "RUNNING".equals(job.status)
              ? "It's already running, so it can't be cancelled; it finishes on its own."
              : "It has already finished.");
    }
    job.future.cancel(false);
    job.status = "CANCELLED";
    job.finishedAt = now();
    log.info("AI job {} cancelled", id);
    return toDto(job, true);
  }

  private void run(Job job, Callable<?> work) {
    synchronized (this) {
      if (!"WAITING".equals(job.status)) return;
      job.status = "RUNNING";
      job.startedAt = now();
    }
    try {
      job.result = work.call();
      job.status = "DONE";
      job.finishedAt = now();
      remember(job.kind, Duration.between(job.startedAt, job.finishedAt).toMillis());
      log.info("AI job {} done: {} for {}", job.id, job.kind, job.subjectId);
    } catch (Exception e) {
      job.error = errorOf(e);
      job.status = "FAILED";
      job.finishedAt = now();
      log.warn("AI job {} failed: {} for {}: {}", job.id, job.kind, job.subjectId, e.getMessage());
    }
  }

  private static AiJobDto.AiJobError errorOf(Exception e) {
    var b = AiJobDto.AiJobError.builder()
        .message(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
    if (e instanceof ContextLengthExceededException c) {
      b.errorCode("CONTEXT_LENGTH_EXCEEDED")
          .promptText(c.getPrompt())
          .promptTokens(c.getPromptTokens())
          .contextLength(c.getContextLength());
    } else if (e instanceof LlmException l && l.getErrorCode() != null) {
      b.errorCode(l.getErrorCode().name());
    }
    return b.build();
  }

  private void remember(String kind, long ms) {
    Deque<Long> d = recentMs.computeIfAbsent(kind, k -> new ArrayDeque<>());
    synchronized (d) {
      d.addLast(ms);
      while (d.size() > TYPICAL_OF) d.removeFirst();
    }
  }

  private Long typicalMs(String kind) {
    Deque<Long> d = recentMs.get(kind);
    if (d == null) return null;
    List<Long> s;
    synchronized (d) {
      if (d.isEmpty()) return null;
      s = new ArrayList<>(d);
    }
    s.sort(null);
    return s.get(s.size() / 2);
  }

  private synchronized Integer position(Job job) {
    if (!"WAITING".equals(job.status)) return null;
    int ahead = 1;
    for (Job j : jobs.values()) {
      if ("WAITING".equals(j.status) && j.createdAt.isBefore(job.createdAt)) ahead++;
    }
    return ahead;
  }

  private Job find(UUID id) {
    Job job = jobs.get(id);
    if (job == null) throw new ResourceNotFoundException("No such AI job (finished ones are kept 30 minutes): " + id);
    return job;
  }

  private void evictOld() {
    Instant cutoff = now().minus(KEEP);
    jobs.values().removeIf(j -> j.finishedAt != null && j.finishedAt.isBefore(cutoff));
  }

  private Instant now() {
    return clock.instant();
  }

  private AiJobDto toDto(Job j, boolean full) {
    return AiJobDto.builder()
        .id(j.id).kind(j.kind).subjectId(j.subjectId).subjectName(j.subjectName)
        .trigger(j.trigger).requestedBy(j.requestedBy).status(j.status).position(position(j))
        .createdAt(j.createdAt).startedAt(j.startedAt).finishedAt(j.finishedAt)
        .typicalMs(typicalMs(j.kind))
        .result(full ? j.result : null)
        .error(j.error == null ? null : full ? j.error : AiJobDto.AiJobError.builder()
            .message(j.error.getMessage()).errorCode(j.error.getErrorCode()).build())
        .build();
  }

  private static final class Job {
    final UUID id;
    final String kind;
    final UUID subjectId;
    final String subjectName;
    final String trigger;
    final String requestedBy;
    final Instant createdAt;
    volatile String status = "WAITING";
    volatile Instant startedAt;
    volatile Instant finishedAt;
    volatile Object result;
    volatile AiJobDto.AiJobError error;
    volatile Future<?> future;

    Job(UUID id, String kind, UUID subjectId, String subjectName, String trigger, String requestedBy, Instant createdAt) {
      this.id = id;
      this.kind = kind;
      this.subjectId = subjectId;
      this.subjectName = subjectName;
      this.trigger = trigger;
      this.requestedBy = requestedBy;
      this.createdAt = createdAt;
    }

    boolean active() {
      return "WAITING".equals(status) || "RUNNING".equals(status);
    }
  }
}
