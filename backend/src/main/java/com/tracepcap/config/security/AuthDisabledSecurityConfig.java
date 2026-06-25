package com.tracepcap.config.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Default security configuration used when {@code tracepcap.auth.enabled} is {@code false} or unset.
 *
 * <p>Spring Security is on the classpath (for the resource-server option), which would otherwise
 * lock everything down behind generated-password HTTP Basic. This chain explicitly permits all
 * requests so the application behaves exactly as it did before auth existed — letting deployments
 * such as Lanturn run with no login.
 *
 * @see AuthEnabledSecurityConfig the JWT-gated counterpart used when auth is on
 */
@Configuration
@EnableWebSecurity
@ConditionalOnProperty(
    prefix = "tracepcap.auth",
    name = "enabled",
    havingValue = "false",
    matchIfMissing = true)
public class AuthDisabledSecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable)
        .cors(Customizer.withDefaults())
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
    return http.build();
  }
}
