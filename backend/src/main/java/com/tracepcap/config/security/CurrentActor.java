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
// Registered here, not only on AuthEnabledSecurityConfig: isAdmin() needs the properties with login
// off too (SYSTEM_SETTINGS_EDITABLE), when that config isn't loaded.
@Component
@org.springframework.boot.context.properties.EnableConfigurationProperties(AuthProperties.class)
public class CurrentActor {

  /** The Keycloak client role that marks an admin (#915). A client role, so it's namespaced. */
  public static final String ADMIN_ROLE = "admin";

  private final AuthProperties authProperties;

  public CurrentActor(AuthProperties authProperties) {
    this.authProperties = authProperties;
  }

  /** Whether login is on for this install. */
  public boolean authEnabled() {
    return authProperties.isEnabled();
  }

  /**
   * Whether the caller is an admin (#915).
   *
   * <p>Login on: the token carries the client role {@link #ADMIN_ROLE} on the configured client
   * ({@code resource_access.<client-id>.roles}). Keycloak is the only place admin is granted.
   *
   * <p>Login off: there are no roles, so admin is the deployer's call. Everyone is an admin when
   * {@code SYSTEM_SETTINGS_EDITABLE=true}, and no one otherwise.
   */
  public boolean isAdmin() {
    if (!authProperties.isEnabled()) return authProperties.isSystemSettingsEditable();
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth == null || !auth.isAuthenticated() || isAnonymous(auth)) return false;
    if (!(auth.getPrincipal() instanceof Jwt jwt)) return false;
    Object resourceAccess = jwt.getClaims().get("resource_access");
    if (!(resourceAccess instanceof java.util.Map<?, ?> clients)) return false;
    Object client = clients.get(authProperties.getClientId());
    if (!(client instanceof java.util.Map<?, ?> clientClaims)) return false;
    Object roles = clientClaims.get("roles");
    return roles instanceof java.util.Collection<?> list && list.contains(ADMIN_ROLE);
  }

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

  /** The profile everyone shares when there is no logged-in account (login off). */
  public static final String SHARED_PROFILE = "shared";

  /**
   * Whose personal preferences this request reads and writes (#915). The token's stable subject
   * id when logged in (not the username, which an admin can rename), or {@link #SHARED_PROFILE}
   * when there is no account. With login off everyone shares one profile, by design.
   */
  public String profileKey() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth == null || !auth.isAuthenticated() || isAnonymous(auth)) return SHARED_PROFILE;
    if (auth.getPrincipal() instanceof Jwt jwt
        && jwt.getSubject() != null
        && !jwt.getSubject().isBlank()) {
      return "sub:" + jwt.getSubject();
    }
    String name = auth.getName();
    return (name == null || name.isBlank()) ? SHARED_PROFILE : "name:" + name;
  }

  /** Spring inserts an {@code anonymousUser} authentication on permit-all chains; that is not a who. */
  private boolean isAnonymous(Authentication auth) {
    return "anonymousUser".equals(auth.getPrincipal());
  }
}
