package com.tracepcap.config;

import java.util.Arrays;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerTypePredicate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Web configuration including CORS and the global API version prefix */
@Configuration
public class WebConfig implements WebMvcConfigurer {

  /** Single source of truth for the API base path + version. Bump here to cut a new version. */
  public static final String API_PREFIX = "/api/v1";

  /**
   * Prefixes every controller in the application's base package with {@link #API_PREFIX}, so
   * controllers declare version-agnostic paths (e.g. {@code @RequestMapping("/files")}) and the
   * version lives in exactly one place. Springdoc/Swagger controllers are excluded (different
   * package), keeping their endpoints unversioned.
   */
  @Override
  public void configurePathMatch(PathMatchConfigurer configurer) {
    configurer.addPathPrefix(
        API_PREFIX, HandlerTypePredicate.forBasePackage("com.tracepcap"));
  }

  // Default to empty: the shipped deployment serves the SPA and proxies /api through the same
  // nginx origin, so browser→API calls are same-origin and never trigger CORS. The prod profile
  // sets this from ${CORS_ALLOWED_ORIGINS} with no default, so leaving it unset must not crash the
  // app — an empty value simply registers no cross-origin allowance. Set it only for a genuinely
  // cross-origin frontend (e.g. a separately-hosted SPA). The dev profile keeps localhost origins.
  @Value("${cors.allowed-origins:}")
  private String allowedOrigins;

  @Value("${cors.allowed-methods}")
  private String allowedMethods;

  @Value("${cors.allowed-headers}")
  private String allowedHeaders;

  @Value("${cors.allow-credentials}")
  private boolean allowCredentials;

  @Value("${cors.max-age}")
  private long maxAge;

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    // Trim and drop empty tokens per origin: a value like "https://a.example, https://b.example"
    // must not register " https://b.example" (leading space) as an origin, and stray leading/
    // trailing commas must not yield empty origins. No valid origins (the same-origin prod
    // default) → register no CORS mapping at all; an empty/blank list with allowCredentials=true
    // is an invalid configuration anyway, so skipping is the correct no-op.
    String[] origins =
        allowedOrigins == null
            ? new String[0]
            : Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toArray(String[]::new);
    if (origins.length == 0) {
      return;
    }
    registry
        .addMapping("/api/**")
        .allowedOrigins(origins)
        .allowedMethods(allowedMethods.split(","))
        .allowedHeaders(allowedHeaders.split(","))
        .allowCredentials(allowCredentials)
        .maxAge(maxAge);
  }
}
