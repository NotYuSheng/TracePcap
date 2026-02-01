package com.tracepcap.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

/**
 * LLM API configuration (OpenAI-compatible format)
 */
@Configuration
@ConfigurationProperties(prefix = "llm")
@Data
public class LlmConfig {

    private ApiConfig api;
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
    public static class RetryConfig {
        private Integer maxAttempts;
        private Long backoffMs;
    }

    @Bean
    public RestTemplate llmRestTemplate() {
        return new RestTemplate();
    }
}
