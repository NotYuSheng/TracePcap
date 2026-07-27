package com.tracepcap.config.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Resolves <em>who</em> is performing the current request, for the audit trail on human actions
 * (adjudication overrides, appended evidence, confirmed labels).
 *
 * <p><b>One place, server-side, never the client.</b> The actor comes from the validated JWT in the
 * security context — never from a request body or header a caller could forge. Every writer that
 * records "who" goes through here rather than reaching into {@link SecurityContextHolder} itself, so
 * the resolution rule (and its auth-off fallback) lives in exactly one file.
 *
 * <p><b>Degrades, does not break.</b> Auth is off by default ({@code tracepcap.auth.enabled=false},
 * see {@link AuthDisabledSecurityConfig}); then there is no principal and {@link #username()} returns
 * {@link #SYSTEM}. The feature must work without a login — an unattributed action is recorded as
 * "system", not rejected.
 */
@Component
public class CurrentActor {

  /** Recorded when there is no authenticated principal (auth disabled, or an internal caller). */
  public static final String SYSTEM = "system";

  /**
   * The current user's stable display name, or {@link #SYSTEM} when unauthenticated.
   *
   * <p>Prefers the Keycloak {@code preferred_username} claim (a human-readable login), falling back
   * to {@code sub} (the opaque subject id) when the token carries no username, and finally to the
   * {@link Authentication#getName()} for non-JWT principals.
   */
  public String username() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth == null || !auth.isAuthenticated() || isAnonymous(auth)) {
      return SYSTEM;
    }
    if (auth.getPrincipal() instanceof Jwt jwt) {
      String preferred = jwt.getClaimAsString("preferred_username");
      if (preferred != null && !preferred.isBlank()) return preferred;
      String subject = jwt.getSubject();
      if (subject != null && !subject.isBlank()) return subject;
    }
    String name = auth.getName();
    return (name == null || name.isBlank()) ? SYSTEM : name;
  }

  /** Spring inserts an {@code anonymousUser} authentication on permit-all chains; that is not a who. */
  private boolean isAnonymous(Authentication auth) {
    return "anonymousUser".equals(auth.getPrincipal());
  }
}
