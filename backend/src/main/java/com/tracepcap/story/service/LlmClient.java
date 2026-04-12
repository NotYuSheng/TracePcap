package com.tracepcap.story.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.tracepcap.common.exception.ContextLengthExceededException;
import com.tracepcap.common.exception.LlmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.tracepcap.config.LlmConfig;
import jakarta.annotation.PostConstruct;
import java.util.List;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/** Client for communicating with OpenAI-compatible LLM APIs */
@Slf4j
@Service
@RequiredArgsConstructor
public class LlmClient {

  private final LlmConfig llmConfig;
  private final RestTemplate llmRestTemplate;
  private volatile Integer effectiveMaxTokens;
  private volatile Integer modelContextLength;

  /**
   * Query the LLM server for model capabilities on startup. Runs in a background thread so it does
   * not delay application startup when the LLM server is unavailable.
   */
  @PostConstruct
  public void initializeModelCapabilities() {
    // Set a safe default immediately so the app is usable before the background check finishes
    effectiveMaxTokens = llmConfig.getApi().getMaxTokens();

    Thread.ofVirtual()
        .name("llm-capability-check")
        .start(
            () -> {
              try {
                // If LLM_CONTEXT_LENGTH is explicitly configured, use it directly and skip
                // the /v1/models auto-detection call.
                if (llmConfig.getApi().getContextLength() != null) {
                  modelContextLength = llmConfig.getApi().getContextLength();
                  log.info(
                      "Using configured context length for model '{}': {}",
                      llmConfig.getApi().getModel(),
                      modelContextLength);
                } else {
                  log.info("Querying LLM server for model capabilities...");
                  ModelInfo modelInfo = queryModelCapabilities();
                  if (modelInfo != null && modelInfo.getContextLength() != null) {
                    modelContextLength = modelInfo.getContextLength();
                    log.info(
                        "Auto-detected context length for model '{}': {}",
                        llmConfig.getApi().getModel(),
                        modelContextLength);
                  } else {
                    log.warn(
                        "Could not determine model context length, using configured max_tokens: {}",
                        llmConfig.getApi().getMaxTokens());
                  }
                }

                if (modelContextLength != null) {
                  // Guard: cap effectiveMaxTokens so it never exceeds 80% of the context window.
                  // LLM_MAX_TOKENS controls response length; this guard prevents accidentally
                  // reserving more tokens for the response than the context window can support.
                  int recommendedMaxTokens = (int) (modelContextLength * 0.8);
                  effectiveMaxTokens =
                      Math.min(llmConfig.getApi().getMaxTokens(), recommendedMaxTokens);

                  log.info(
                      "Model '{}': context_length={}, configured_max_tokens={}, effective_max_tokens={}",
                      llmConfig.getApi().getModel(),
                      modelContextLength,
                      llmConfig.getApi().getMaxTokens(),
                      effectiveMaxTokens);

                  if (llmConfig.getApi().getMaxTokens() > recommendedMaxTokens) {
                    log.warn(
                        "Configured LLM_MAX_TOKENS ({}) exceeds 80% of context window ({}). Using {} tokens for responses.",
                        llmConfig.getApi().getMaxTokens(),
                        modelContextLength,
                        effectiveMaxTokens);
                  }
                }
              } catch (Exception e) {
                log.warn(
                    "Failed to initialise model capabilities: {}. Using configured max_tokens: {}",
                    e.getMessage(),
                    llmConfig.getApi().getMaxTokens());
              }
            });
  }

  /** Query the LLM server for model information */
  private ModelInfo queryModelCapabilities() {
    try {
      String url = llmConfig.getApi().getBaseUrl() + "/models";

      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(llmConfig.getApi().getApiKey());
      HttpEntity<Void> entity = new HttpEntity<>(headers);

      ResponseEntity<ModelsResponse> response =
          llmRestTemplate.exchange(url, HttpMethod.GET, entity, ModelsResponse.class);

      if (response.getBody() != null && response.getBody().getData() != null) {
        // Find the configured model in the response
        String configuredModel = llmConfig.getApi().getModel();
        for (ModelInfo model : response.getBody().getData()) {
          if (model.getId() != null && model.getId().equals(configuredModel)) {
            return model;
          }
        }

        // If exact match not found, return first model
        if (!response.getBody().getData().isEmpty()) {
          ModelInfo firstModel = response.getBody().getData().get(0);
          log.warn(
              "Configured model '{}' not found in models list. Using first available model: '{}'",
              configuredModel,
              firstModel.getId());
          return firstModel;
        }
      }
    } catch (Exception e) {
      log.debug("Error querying /models endpoint: {}", e.getMessage());
    }

    return null;
  }

  /** Get the effective max tokens (adjusted based on model capabilities) */
  public Integer getEffectiveMaxTokens() {
    return effectiveMaxTokens != null ? effectiveMaxTokens : llmConfig.getApi().getMaxTokens();
  }

  /** Get the model's context length */
  public Integer getModelContextLength() {
    return modelContextLength;
  }

  /**
   * Generate a completion from the LLM
   *
   * @param systemPrompt the system prompt
   * @param userPrompt the user prompt
   * @return the generated text
   */
  public String generateCompletion(String systemPrompt, String userPrompt) {
    try {
      log.info("Sending request to LLM API: {}", llmConfig.getApi().getBaseUrl());

      // Create request payload in OpenAI format
      ChatCompletionRequest request =
          ChatCompletionRequest.builder()
              .model(llmConfig.getApi().getModel())
              .messages(
                  List.of(new Message("system", systemPrompt), new Message("user", userPrompt)))
              .temperature(llmConfig.getApi().getTemperature())
              .maxTokens(getEffectiveMaxTokens())
              .build();

      log.debug("Generating completion with max_tokens: {}", getEffectiveMaxTokens());

      // Set headers
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      headers.setBearerAuth(llmConfig.getApi().getApiKey());

      HttpEntity<ChatCompletionRequest> entity = new HttpEntity<>(request, headers);

      // Make API call
      String url = llmConfig.getApi().getBaseUrl() + "/chat/completions";
      ResponseEntity<ChatCompletionResponse> response =
          llmRestTemplate.exchange(url, HttpMethod.POST, entity, ChatCompletionResponse.class);

      // Extract response
      if (response.getBody() != null
          && response.getBody().getChoices() != null
          && !response.getBody().getChoices().isEmpty()) {

        var choice = response.getBody().getChoices().get(0);
        String content = choice.getMessage() != null ? choice.getMessage().getContent() : null;
        if (content == null) throw new LlmException("Empty response from LLM API");
        log.info("Successfully received LLM response, length: {}", content.length());
        return content;
      }

      throw new LlmException("Empty response from LLM API");

    } catch (LlmException e) {
      throw e;
    } catch (Exception e) {
      // Detect context-length exceeded (OpenAI-compatible 400 response)
      String msg = e.getMessage() != null ? e.getMessage() : "";
      if (msg.contains("maximum context length")) {
        int promptTokens = parseGroup(msg, "\\((\\d+) in the messages");
        int contextTokens = parseGroup(msg, "maximum context length is (\\d+)");
        if (contextTokens == 0) contextTokens = parseGroup(msg, "context length is (\\d+)");
        throw new ContextLengthExceededException(promptTokens, contextTokens, userPrompt);
      }
      log.error("Error calling LLM API", e);
      throw new LlmException("Failed to reach the LLM service: " + e.getMessage(), e);
    }
  }

  private static int parseGroup(String text, String regex) {
    Matcher m = Pattern.compile(regex).matcher(text);
    return m.find() ? Integer.parseInt(m.group(1)) : 0;
  }

  /** OpenAI Chat Completion Request format */
  @Data
  @lombok.Builder
  private static class ChatCompletionRequest {
    private String model;
    private List<Message> messages;
    private Double temperature;

    @JsonProperty("max_tokens")
    private Integer maxTokens;
  }

  /** Message in the conversation */
  @Data
  @lombok.AllArgsConstructor
  private static class Message {
    private String role;
    private String content;
  }

  /** OpenAI Chat Completion Response format */
  @Data
  private static class ChatCompletionResponse {
    private List<Choice> choices;
  }

  /** Choice in the response */
  @Data
  private static class Choice {
    private Message message;
  }

  /** Models list response */
  @Data
  private static class ModelsResponse {
    private List<ModelInfo> data;
  }

  /** Model information */
  @Data
  private static class ModelInfo {
    private String id;
    private String object;
    private Long created;

    @JsonProperty("owned_by")
    private String ownedBy;

    @JsonProperty("context_length")
    private Integer contextLength;

    @JsonProperty("max_tokens")
    private Integer maxTokens;
  }
}
