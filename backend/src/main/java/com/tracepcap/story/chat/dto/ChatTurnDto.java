package com.tracepcap.story.chat.dto;

import java.util.List;
import java.util.UUID;
import lombok.Builder;
import lombok.Value;

/**
 * One question and the work toward its answer. While {@code status} is RUNNING, {@code steps} grows
 * as tools run; at DONE the answer is set, at FAILED the error.
 */
@Value
@Builder
public class ChatTurnDto {
  UUID id;
  String status;
  List<ChatStepDto> steps;
  String answer;
  List<String> followUpQuestions;
  /** Display filters the tools checked and found valid this turn, newest last. */
  List<FilterDto> filters;
  /** False when the LLM answered without tools (they're off, or its server doesn't support them). */
  boolean toolsOffered;
  String error;
  /** LLM_UNREACHABLE, LLM_TIMEOUT, OUTPUT_TRUNCATED, LLM_BAD_RESPONSE, CONTEXT_TOO_LONG or null. */
  String errorCode;
  long elapsedMs;

  /** One tool call: what was asked, and a line on what came back. */
  @Value
  @Builder
  public static class ChatStepDto {
    String tool;
    String label;
    /** The arguments, as the model sent them (JSON). */
    String arguments;
    /** RUNNING, DONE or FAILED. */
    String status;
    String summary;
    Long ms;
  }

  @Value
  public static class FilterDto {
    String expression;
    Integer matches;
  }
}
