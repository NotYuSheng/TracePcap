package com.tracepcap.story.dto;

import java.util.List;
import lombok.Builder;
import lombok.Value;

/** The connection test's steps, in order, and the models the server offers. */
@Value
@Builder
public class LlmTestResult {
  /** Nothing failed (warnings allowed). */
  boolean ok;

  List<Step> steps;
  /** The server's models (from /models), for picking one; empty when it couldn't be listed. */
  List<String> models;
  /** The URL and model that were tested, after filling blanks from the current settings. */
  String baseUrl;

  String model;

  /** One check: reach, key, model, reply, and tools when the server says. */
  @Value
  @Builder
  public static class Step {
    String key;
    String label;
    /** OK, WARN (works, but not as set: another model answered, no tools), FAIL or SKIPPED. */
    String status;
    /** What happened, in words the person can act on. */
    String detail;
    /** How long it took, in ms; null when skipped. */
    Long ms;
  }
}
