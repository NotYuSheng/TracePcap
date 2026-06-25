package com.tracepcap.config.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Authentication configuration, bound from {@code tracepcap.auth.*}.
 *
 * <p>When {@link #enabled} is {@code false} (the default) the application behaves exactly as it does
 * without any security layer — every request is permitted. When enabled, the API is gated behind a
 * Keycloak-issued JWT validated as an OAuth2 resource server.
 */
@ConfigurationProperties(prefix = "tracepcap.auth")
public class AuthProperties {

  /** Master switch. Default {@code false} so existing (auth-less) deployments are unaffected. */
  private boolean enabled = false;

  /**
   * The OIDC issuer URI as it appears in the token's {@code iss} claim — i.e. the browser-facing
   * Keycloak URL (e.g. {@code http://localhost:8081/realms/tracepcap}). Used to validate the issuer.
   */
  private String issuerUri;

  /**
   * Optional JWKS endpoint used to fetch signing keys. In Docker the browser and the backend reach
   * Keycloak via different hostnames; set this to the backend-reachable URL (e.g.
   * {@code http://keycloak:8080/realms/tracepcap/protocol/openid-connect/certs}) while {@link
   * #issuerUri} stays the public one. When blank, keys are discovered from {@link #issuerUri}.
   */
  private String jwkSetUri;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String getIssuerUri() {
    return issuerUri;
  }

  public void setIssuerUri(String issuerUri) {
    this.issuerUri = issuerUri;
  }

  public String getJwkSetUri() {
    return jwkSetUri;
  }

  public void setJwkSetUri(String jwkSetUri) {
    this.jwkSetUri = jwkSetUri;
  }
}
