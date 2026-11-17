package com.tracepcap.common.aijob;

import java.time.Instant;
import java.util.UUID;
import lombok.Builder;
import lombok.Value;

/** One piece of AI work: waiting for the model, running, or finished in the last 30 minutes. */
@Value
@Builder
public class AiJobDto {
  UUID id;
  /** What it is, e.g. {@code STORY} or {@code INSIGHTS}. */
  String kind;
  /** Where its answer lands: a capture for a story, a monitored network for insights. */
  UUID subjectId;
  /** Something finer within it, when the job is about one host, subnet or conversation. */
  String subjectKey;
  /** That thing's name, for the header's list. */
  String subjectName;
  /** {@code USER} when someone asked for it, {@code UPLOAD} when an upload option did. */
  String trigger;
  /** Who asked for it ({@code system} with login off). */
  String requestedBy;
  /** {@code WAITING}, {@code RUNNING}, {@code DONE}, {@code FAILED} or {@code CANCELLED}. */
  String status;
  /** While waiting: its place in line, 1 being next. */
  Integer position;
  Instant createdAt;
  Instant startedAt;
  Instant finishedAt;
  /** How long this kind usually takes here (the median of the last few), when known. */
  Long typicalMs;
  /** The answer once DONE: the kind's own DTO (a story, an insight). Left out of the list. */
  Object result;
  /** Why it FAILED. */
  AiJobError error;

  @Value
  @Builder
  public static class AiJobError {
    String message;
    /** e.g. {@code CONTEXT_LENGTH_EXCEEDED}, {@code LLM_TIMEOUT}, {@code LLM_UNREACHABLE}. */
    String errorCode;
    /** With CONTEXT_LENGTH_EXCEEDED: the prompt, so it can be cut down and sent again. */
    String promptText;
    Integer promptTokens;
    Integer contextLength;
  }
}
