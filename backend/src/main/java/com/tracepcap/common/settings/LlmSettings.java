package com.tracepcap.common.settings;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * The LLM connection as it is now: the in-app value where one is set (Settings › System), else the
 * deployment's. Read on every call, so a change applies to the next one without a restart.
 */
@Component
@RequiredArgsConstructor
public class LlmSettings {

  private final RuntimePolicy runtimePolicy;

  /** The API's base URL, without a trailing slash (the client appends /models and so on). */
  public String baseUrl() {
    return runtimePolicy.getString(EditablePolicy.LLM_API_BASE_URL).replaceAll("/+$", "");
  }

  public String apiKey() {
    return runtimePolicy.getString(EditablePolicy.LLM_API_KEY);
  }

  public String model() {
    return runtimePolicy.getString(EditablePolicy.LLM_MODEL);
  }

  public double temperature() {
    return runtimePolicy.getDouble(EditablePolicy.LLM_TEMPERATURE);
  }

  public int maxTokens() {
    return runtimePolicy.getInt(EditablePolicy.LLM_MAX_TOKENS);
  }

  public int timeoutSeconds() {
    return runtimePolicy.getInt(EditablePolicy.LLM_TIMEOUT);
  }

  /** auto, on or off. */
  public String toolCalling() {
    String v = runtimePolicy.getString(EditablePolicy.LLM_TOOL_CALLING);
    return v == null ? "auto" : v.trim().toLowerCase(java.util.Locale.ROOT);
  }
}
