package com.tracepcap.story.service;

import com.fasterxml.jackson.annotation.JsonProperty;
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
  private Integer effectiveMaxTokens;
  private Integer modelContextLength;

  /** Query the LLM server for model capabilities on startup */
  @PostConstruct
  public void initializeModelCapabilities() {
    try {
      log.info("Querying LLM server for model capabilities...");
      ModelInfo modelInfo = queryModelCapabilities();

      if (modelInfo != null && modelInfo.getContextLength() != null) {
        modelContextLength = modelInfo.getContextLength();

        // Set effective max tokens to 80% of context length to leave room for prompt
        // or use configured value if it's smaller
        int recommendedMaxTokens = (int) (modelContextLength * 0.8);
        effectiveMaxTokens = Math.min(llmConfig.getApi().getMaxTokens(), recommendedMaxTokens);

        log.info(
            "Model '{}' capabilities detected: context_length={}, configured_max_tokens={}, effective_max_tokens={}",
            llmConfig.getApi().getModel(),
            modelContextLength,
            llmConfig.getApi().getMaxTokens(),
            effectiveMaxTokens);

        if (llmConfig.getApi().getMaxTokens() > recommendedMaxTokens) {
          log.warn(
              "Configured max_tokens ({}) exceeds recommended limit ({}). Using {} tokens.",
              llmConfig.getApi().getMaxTokens(),
              recommendedMaxTokens,
              effectiveMaxTokens);
        }
      } else {
        log.warn(
            "Could not determine model capabilities, using configured max_tokens: {}",
            llmConfig.getApi().getMaxTokens());
        effectiveMaxTokens = llmConfig.getApi().getMaxTokens();
      }
    } catch (Exception e) {
      log.warn(
          "Failed to query model capabilities: {}. Using configured max_tokens: {}",
          e.getMessage(),
          llmConfig.getApi().getMaxTokens());
      effectiveMaxTokens = llmConfig.getApi().getMaxTokens();
    }
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

        String content = response.getBody().getChoices().get(0).getMessage().getContent();
        log.info("Successfully received LLM response, length: {}", content.length());
        return content;
      }

      throw new RuntimeException("Empty response from LLM API");

    } catch (Exception e) {
      log.error("Error calling LLM API", e);
      throw new RuntimeException("Failed to generate LLM completion: " + e.getMessage(), e);
    }
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
