package com.tracepcap.config.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/** Whose preferences a request reads and writes (#915). */
class CurrentActorProfileKeyTest {

  private final CurrentActor actor = new CurrentActor();

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void loginOff_everyoneSharesOneProfile() {
    assertThat(actor.profileKey()).isEqualTo(CurrentActor.SHARED_PROFILE);

    SecurityContextHolder.getContext().setAuthentication(
        new AnonymousAuthenticationToken("k", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));
    assertThat(actor.profileKey()).isEqualTo(CurrentActor.SHARED_PROFILE);
  }

  @Test
  void loginOn_theProfileIsTheAccountsStableSubject_notItsUsername() {
    Jwt jwt =
        new Jwt("t", Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "none"),
            Map.of("sub", "f3a1-uuid", "preferred_username", "alice"));
    SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));

    // A renamed account keeps its preferences: they hang off the subject id.
    assertThat(actor.profileKey()).isEqualTo("sub:f3a1-uuid");
  }
}
