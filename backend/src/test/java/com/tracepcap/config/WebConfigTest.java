package com.tracepcap.config;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.config.annotation.CorsRegistration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

/**
 * Guards the CORS behaviour that lets the prod Spring profile boot without CORS_ALLOWED_ORIGINS.
 * The shipped stack is same-origin (nginx serves the SPA and proxies /api), so an unset/blank
 * origins value must register NO CORS mapping rather than crash or misconfigure the registry.
 */
class WebConfigTest {

  private WebConfig webConfigWith(String origins) {
    WebConfig config = new WebConfig();
    ReflectionTestUtils.setField(config, "allowedOrigins", origins);
    ReflectionTestUtils.setField(config, "allowedMethods", "GET,POST");
    ReflectionTestUtils.setField(config, "allowedHeaders", "*");
    ReflectionTestUtils.setField(config, "allowCredentials", true);
    ReflectionTestUtils.setField(config, "maxAge", 3600L);
    return config;
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "   "})
  void blankOriginsRegistersNoCorsMapping(String origins) {
    CorsRegistry registry = mock(CorsRegistry.class);

    webConfigWith(origins).addCorsMappings(registry);

    verify(registry, never()).addMapping(org.mockito.ArgumentMatchers.anyString());
  }

  @Test
  void nullOriginsRegistersNoCorsMapping() {
    CorsRegistry registry = mock(CorsRegistry.class);

    webConfigWith(null).addCorsMappings(registry);

    verify(registry, never()).addMapping(org.mockito.ArgumentMatchers.anyString());
  }

  private CorsRegistration fluentRegistration() {
    return mock(CorsRegistration.class, invocation ->
        // Fluent builder — every chained call returns the same registration.
        invocation.getMethod().getReturnType().equals(CorsRegistration.class)
            ? invocation.getMock()
            : null);
  }

  @Test
  void configuredOriginsRegisterCorsMapping() {
    CorsRegistry registry = mock(CorsRegistry.class);
    CorsRegistration registration = fluentRegistration();
    when(registry.addMapping("/api/**")).thenReturn(registration);

    webConfigWith("https://app.example.com,https://admin.example.com")
        .addCorsMappings(registry);

    verify(registry).addMapping("/api/**");
    verify(registration)
        .allowedOrigins("https://app.example.com", "https://admin.example.com");
  }

  @Test
  void originsAreTrimmedAndEmptyTokensDropped() {
    CorsRegistry registry = mock(CorsRegistry.class);
    CorsRegistration registration = fluentRegistration();
    when(registry.addMapping("/api/**")).thenReturn(registration);

    // Whitespace around the comma + leading/trailing/duplicated commas.
    webConfigWith(" https://app.example.com , https://admin.example.com ,, ")
        .addCorsMappings(registry);

    // Each origin registered without surrounding whitespace, no empty tokens.
    verify(registration)
        .allowedOrigins("https://app.example.com", "https://admin.example.com");
  }

  @Test
  void whitespaceAndCommaOnlyOriginsRegisterNoMapping() {
    CorsRegistry registry = mock(CorsRegistry.class);

    // Only separators/whitespace → no valid origin → no mapping.
    webConfigWith(" , , ").addCorsMappings(registry);

    verify(registry, never()).addMapping(org.mockito.ArgumentMatchers.anyString());
  }
}
