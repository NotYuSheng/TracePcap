package com.tracepcap.config;

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

  @Value("${cors.allowed-origins}")
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
    registry
        .addMapping("/api/**")
        .allowedOrigins(allowedOrigins.split(","))
        .allowedMethods(allowedMethods.split(","))
        .allowedHeaders(allowedHeaders.split(","))
        .allowCredentials(allowCredentials)
        .maxAge(maxAge);
  }
}
