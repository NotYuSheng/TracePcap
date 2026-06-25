package com.tracepcap.config.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

/**
 * Security configuration active only when {@code tracepcap.auth.enabled=true}.
 *
 * <p>Gates the whole API behind a valid Keycloak JWT (stateless OAuth2 resource server). Swagger,
 * the actuator health/info endpoints and CORS pre-flight requests stay open. Data is shared across
 * all authenticated users (no per-user scoping in this version).
 *
 * @see AuthDisabledSecurityConfig the permit-all counterpart used when auth is off
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(AuthProperties.class)
@ConditionalOnProperty(prefix = "tracepcap.auth", name = "enabled", havingValue = "true")
public class AuthEnabledSecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable)
        .cors(Customizer.withDefaults())
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(HttpMethod.OPTIONS, "/**")
                    .permitAll()
                    .requestMatchers("/actuator/health/**", "/actuator/info")
                    .permitAll()
                    .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()));
    return http.build();
  }

  /**
   * Builds the JWT decoder. When a JWKS URI is configured we fetch keys from it (the
   * backend-reachable Keycloak URL) while still validating the {@code iss} claim against the public
   * issuer — this decouples key retrieval from issuer validation, which matters in Docker where the
   * browser and backend address Keycloak by different hostnames. Otherwise both are discovered from
   * the issuer URI.
   */
  @Bean
  JwtDecoder jwtDecoder(AuthProperties props) {
    if (StringUtils.hasText(props.getJwkSetUri())) {
      NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(props.getJwkSetUri()).build();
      if (StringUtils.hasText(props.getIssuerUri())) {
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(props.getIssuerUri()));
      }
      return decoder;
    }
    return JwtDecoders.fromIssuerLocation(props.getIssuerUri());
  }
}
