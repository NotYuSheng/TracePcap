package com.tracepcap.config;

import com.fasterxml.jackson.core.StreamReadConstraints;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Raises Jackson's default 20MB max-string-length constraint (jackson-databind 2.15+), which
 * otherwise rejects report-generation request bodies carrying a base64-encoded topology diagram
 * PNG once the capture is large/dense enough to push the base64 string past the default. See
 * #792.
 */
@Configuration
public class JacksonConfig {

  @Value("${tracepcap.jackson.max-string-length}")
  private int maxStringLength;

  @Bean
  public Jackson2ObjectMapperBuilderCustomizer streamReadConstraintsCustomizer() {
    return builder ->
        builder.postConfigurer(
            mapper ->
                mapper
                    .getFactory()
                    .setStreamReadConstraints(
                        StreamReadConstraints.builder()
                            .maxStringLength(maxStringLength)
                            .build()));
  }
}
