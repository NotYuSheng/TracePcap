package com.tracepcap.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.config.security.CurrentActor;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;

/** Settings › Users: who signed in, with which roles, and what they add up to. */
class UserDirectoryServiceTest {

  private final SignedInUserRepository repo = mock(SignedInUserRepository.class);
  private final RoleRepository roleRepo = mock(RoleRepository.class);
  private final CurrentActor actor = mock(CurrentActor.class);
  private final UserDirectoryService service = new UserDirectoryService(repo, roleRepo, actor);

  @BeforeEach
  void roles() {
    RoleEntity admin = role("admin", false);
    RoleEntity analyst = role("analyst", true, "SEE_CAPTURES", "ASK_AI", "UPLOAD_CAPTURES");
    RoleEntity viewer = role("viewer", false, "SEE_CAPTURES", "DOWNLOAD_REPORT");
    when(roleRepo.findAllByOrderByPositionDescKeyAsc()).thenReturn(List.of(admin, analyst, viewer));
  }

  @Test
  void withLoginOff_nothingIsRecorded() {
    when(actor.authEnabled()).thenReturn(false);
    service.recordCaller();
    verify(repo, never()).save(any());
  }

  @Test
  void aSignInIsRecorded_thenNotRewrittenForAWhile_unlessItsRolesChange() {
    when(actor.authEnabled()).thenReturn(true);
    when(actor.subject()).thenReturn("sub-1");
    when(actor.username()).thenReturn("ana");
    when(actor.displayName()).thenReturn("Ana A");
    when(actor.roles()).thenReturn(Set.of("analyst"));
    when(repo.findById("sub-1")).thenReturn(Optional.empty());

    service.recordCaller();
    service.recordCaller(); // the app reloads: no second write
    verify(repo, times(1)).save(any());

    when(actor.roles()).thenReturn(Set.of("analyst", "viewer")); // Keycloak gave another role
    service.recordCaller();
    verify(repo, times(2)).save(any());
  }

  @Test
  void theList_showsTracePcapRoles_flagsUnknownOnes_andUsesTheDefaultWhenNoneMatch() {
    LocalDateTime now = LocalDateTime.now();
    SignedInUserEntity both = user("ana", now, "viewer", "analyst", "typo-role");
    SignedInUserEntity none = user("bob", now, "some-other-apps-role");
    SignedInUserEntity admin = user("root", now, "admin");
    when(repo.search(isNull(), any())).thenReturn(new PageImpl<>(List.of(both, none, admin)));

    PagedResponse<UserDto> page = service.list(1, 50, null);
    UserDto ana = page.getData().get(0);
    assertThat(ana.getRoles()).containsExactly("analyst", "viewer");
    assertThat(ana.getUnknownRoles()).containsExactly("typo-role");
    assertThat(ana.isDefaultRole()).isFalse();
    assertThat(ana.getPermissionCount()).isEqualTo(4); // SEE, ASK_AI, UPLOAD, DOWNLOAD_REPORT

    UserDto bob = page.getData().get(1);
    assertThat(bob.getRoles()).containsExactly("analyst");
    assertThat(bob.isDefaultRole()).isTrue();
    assertThat(bob.getUnknownRoles()).containsExactly("some-other-apps-role");

    assertThat(page.getData().get(2).getPermissionCount()).isEqualTo(PermissionAction.values().length);
  }

  private static SignedInUserEntity user(String name, LocalDateTime at, String... roles) {
    return SignedInUserEntity.builder().subject("sub-" + name).username(name)
        .clientRoles(roles).firstSeen(at).lastSeen(at).build();
  }

  private static RoleEntity role(String key, boolean isDefault, String... perms) {
    return RoleEntity.builder().key(key).label(key).builtIn(true).defaultRole(isDefault)
        .permissions(new HashSet<>(List.of(perms))).updatedAt(LocalDateTime.now()).updatedBy("t").build();
  }
}
