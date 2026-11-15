package com.tracepcap.config.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/** Admin is the Keycloak client role with login on, and the deployer's flag with login off (#915). */
class CurrentActorIsAdminTest {

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  private static AuthProperties props(boolean enabled, boolean editable) {
    AuthProperties p = new AuthProperties();
    p.setEnabled(enabled);
    p.setSystemSettingsEditable(editable);
    return p;
  }

  private static void login(Map<String, Object> resourceAccess) {
    Jwt.Builder b =
        Jwt.withTokenValue("t")
            .header("alg", "none")
            .subject("u1")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60));
    if (resourceAccess != null) b.claim("resource_access", resourceAccess);
    SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(b.build(), List.of()));
  }

  @Test
  void loginOff_followsTheFlag() {
    assertThat(new CurrentActor(props(false, false)).isAdmin()).isFalse();
    assertThat(new CurrentActor(props(false, true)).isAdmin()).isTrue();
  }

  @Test
  void loginOn_clientRoleMakesAnAdmin() {
    login(Map.of("tracepcap-frontend", Map.of("roles", List.of("admin"))));
    assertThat(new CurrentActor(props(true, false)).isAdmin()).isTrue();
  }

  @Test
  void loginOn_flagIsIgnored_andOtherClientsOrNoRoleAreNotAdmin() {
    CurrentActor actor = new CurrentActor(props(true, true));
    assertThat(actor.isAdmin()).as("no authentication").isFalse();
    login(null);
    assertThat(actor.isAdmin()).as("no resource_access").isFalse();
    login(Map.of("account", Map.of("roles", List.of("admin"))));
    assertThat(actor.isAdmin()).as("admin on a different client").isFalse();
    login(Map.of("tracepcap-frontend", Map.of("roles", List.of("viewer"))));
    assertThat(actor.isAdmin()).as("other role").isFalse();
  }
}
