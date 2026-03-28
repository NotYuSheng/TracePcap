package com.tracepcap.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/** LLM API configuration (OpenAI-compatible format) */
@Configuration
@ConfigurationProperties(prefix = "llm")
@Data
public class LlmConfig {

  private ApiConfig api;
  private StoryConfig story;
  private RetryConfig retry;

  @Data
  public static class ApiConfig {
    private String baseUrl;
    private String apiKey;
    private String model;
    private Double temperature;
    private Integer maxTokens;
    private Integer timeoutSeconds;
  }

  @Data
  public static class StoryConfig {
    /** Maximum number of conversations included in the story prompt (sorted by traffic volume). */
    private Integer maxConversations = 20;
  }

  @Data
  public static class RetryConfig {
    private Integer maxAttempts;
    private Long backoffMs;
  }

  @Bean
  public RestTemplate llmRestTemplate() {
    int timeoutMs = (api != null && api.getTimeoutSeconds() != null)
        ? api.getTimeoutSeconds() * 1000 : 60_000;
    SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(timeoutMs);
    factory.setReadTimeout(timeoutMs);
    return new RestTemplate(factory);
  }
}
