package com.tracepcap.governance;

import com.tracepcap.config.WebConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Registers {@link RequestAuditInterceptor} on every API path. Here rather than in {@code
 * WebConfig}, so the config module needn't know about governance (no module cycle).
 */
@Configuration
@RequiredArgsConstructor
public class AuditWebConfig implements WebMvcConfigurer {

  private final RequestAuditInterceptor requestAuditInterceptor;

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(requestAuditInterceptor).addPathPatterns(WebConfig.API_PREFIX + "/**");
  }
}
