package com.tracepcap.story.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.tracepcap.config.LlmConfig;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

/**
 * Client for communicating with OpenAI-compatible LLM APIs
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LlmClient {

    private final LlmConfig llmConfig;
    private final RestTemplate llmRestTemplate;

    /**
     * Generate a completion from the LLM
     *
     * @param systemPrompt the system prompt
     * @param userPrompt   the user prompt
     * @return the generated text
     */
    public String generateCompletion(String systemPrompt, String userPrompt) {
        try {
            log.info("Sending request to LLM API: {}", llmConfig.getApi().getBaseUrl());

            // Create request payload in OpenAI format
            ChatCompletionRequest request = ChatCompletionRequest.builder()
                    .model(llmConfig.getApi().getModel())
                    .messages(List.of(
                            new Message("system", systemPrompt),
                            new Message("user", userPrompt)
                    ))
                    .temperature(llmConfig.getApi().getTemperature())
                    .maxTokens(llmConfig.getApi().getMaxTokens())
                    .build();

            // Set headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(llmConfig.getApi().getApiKey());

            HttpEntity<ChatCompletionRequest> entity = new HttpEntity<>(request, headers);

            // Make API call
            String url = llmConfig.getApi().getBaseUrl() + "/chat/completions";
            ResponseEntity<ChatCompletionResponse> response = llmRestTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    entity,
                    ChatCompletionResponse.class
            );

            // Extract response
            if (response.getBody() != null &&
                response.getBody().getChoices() != null &&
                !response.getBody().getChoices().isEmpty()) {

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

    /**
     * OpenAI Chat Completion Request format
     */
    @Data
    @lombok.Builder
    private static class ChatCompletionRequest {
        private String model;
        private List<Message> messages;
        private Double temperature;
        @JsonProperty("max_tokens")
        private Integer maxTokens;
    }

    /**
     * Message in the conversation
     */
    @Data
    @lombok.AllArgsConstructor
    private static class Message {
        private String role;
        private String content;
    }

    /**
     * OpenAI Chat Completion Response format
     */
    @Data
    private static class ChatCompletionResponse {
        private List<Choice> choices;
    }

    /**
     * Choice in the response
     */
    @Data
    private static class Choice {
        private Message message;
    }
}
