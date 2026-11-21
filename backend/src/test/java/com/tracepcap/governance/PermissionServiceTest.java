package com.tracepcap.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.config.security.CurrentActor;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Roles: whose roles apply, what they combine to, and who may change them. */
class PermissionServiceTest {

  private final RoleRepository repo = mock(RoleRepository.class);
  private final CurrentActor actor = mock(CurrentActor.class);
  private final AuditLogService audit = mock(AuditLogService.class);
  private final PermissionService service = new PermissionService(repo, actor, audit);

  private RoleEntity viewer;
  private RoleEntity analyst;
  private RoleEntity lead;
  private RoleEntity admin;

  @BeforeEach
  void roles() {
    viewer = role("viewer", 10, false, PermissionAction.SEE_CAPTURES, PermissionAction.DOWNLOAD_REPORT);
    analyst =
        role("analyst", 20, true,
            PermissionAction.SEE_CAPTURES, PermissionAction.DOWNLOAD_REPORT, PermissionAction.UPLOAD_CAPTURES,
            PermissionAction.ASK_AI, PermissionAction.DELETE_OWN_CAPTURES, PermissionAction.DETECTION_RULES_GLOBAL);
    lead =
        role("lead", 30, false,
            PermissionAction.SEE_CAPTURES, PermissionAction.READ_AUDIT_LOG, PermissionAction.DELETE_ANY_CAPTURES);
    admin = role("admin", 40, false);
    List<RoleEntity> all = List.of(admin, lead, analyst, viewer); // most access first
    when(repo.findAllByOrderByPositionDescKeyAsc()).thenReturn(all);
    for (RoleEntity r : all) when(repo.findById(r.getKey())).thenReturn(Optional.of(r));
    when(repo.findFirstByDefaultRoleTrue()).thenReturn(Optional.of(analyst));
    when(actor.username()).thenReturn("ana");
  }

  private void loginWith(String... roles) {
    when(actor.authEnabled()).thenReturn(true);
    when(actor.roles()).thenReturn(Set.of(roles));
    when(actor.isAdmin()).thenReturn(Arrays.asList(roles).contains("admin"));
  }

  @Test
  void loginOff_everyoneHasEveryRoleButAdmin_andAdminOnlyWithSystemSettingsEditable() {
    when(actor.authEnabled()).thenReturn(false);
    assertThat(service.callerRoles()).extracting(RoleEntity::getKey).containsExactly("lead", "analyst", "viewer");
    assertThat(service.can(PermissionAction.UPLOAD_CAPTURES)).isTrue();
    // As before roles: a lone analyst with login off can still read the log and delete anything.
    assertThat(service.can(PermissionAction.READ_AUDIT_LOG)).isTrue();
    service.requireDeleteCapture(null);
    assertThatThrownBy(() -> service.require(PermissionAction.RETENTION))
        .isInstanceOf(ForbiddenException.class)
        .hasMessageContaining("SYSTEM_SETTINGS_EDITABLE");

    when(actor.isAdmin()).thenReturn(true);
    service.require(PermissionAction.RETENTION);
    assertThat(service.can(PermissionAction.MANAGE_ROLES)).isTrue();
  }

  @Test
  void loginOn_theTokensRolesCombine_andAnUnknownRoleGivesNothing() {
    loginWith("viewer", "lead", "typo-role");
    assertThat(service.callerRoles()).extracting(RoleEntity::getKey).containsExactly("lead", "viewer");
    assertThat(service.can(PermissionAction.DOWNLOAD_REPORT)).isTrue(); // from viewer
    assertThat(service.can(PermissionAction.READ_AUDIT_LOG)).isTrue(); // from lead
    assertThat(service.can(PermissionAction.UPLOAD_CAPTURES)).isFalse(); // neither
  }

  @Test
  void aTokenWithNoTracePcapRole_getsTheDefaultRole() {
    loginWith("some-other-apps-role");
    assertThat(service.callerRoles()).extracting(RoleEntity::getKey).containsExactly("analyst");
    assertThat(service.can(PermissionAction.UPLOAD_CAPTURES)).isTrue();
  }

  @Test
  void theAdminRoleHasEverything_andNoOtherRoleCanManageRoles() {
    loginWith("admin");
    assertThat(service.callerPermissions()).isEqualTo(EnumSet.allOf(PermissionAction.class));

    analyst.getPermissions().add(PermissionAction.MANAGE_ROLES.name()); // even if stored
    loginWith("analyst");
    assertThat(service.can(PermissionAction.MANAGE_ROLES)).isFalse();
  }

  @Test
  void everyoneMaySeeCaptures_evenARoleWithoutTheRow() {
    viewer.getPermissions().clear();
    loginWith("viewer");
    assertThat(service.can(PermissionAction.SEE_CAPTURES)).isTrue();
  }

  @Test
  void refusalSaysWhichRolesTheCallerHas() {
    loginWith("viewer");
    assertThatThrownBy(() -> service.require(PermissionAction.ASK_AI))
        .isInstanceOf(ForbiddenException.class)
        .hasMessageStartingWith("Ask the AI: ")
        .hasMessageContaining("Viewer");
  }

  @Test
  void onlyAdminsChangeRoles() {
    loginWith("lead");
    assertThatThrownBy(() -> service.setPermissions("viewer", Set.of(PermissionAction.ASK_AI)))
        .isInstanceOf(ForbiddenException.class);
    verify(repo, never()).save(any());
  }

  @Test
  void settingARolesPermissions_keepsSeeing_dropsManageRoles_andIsAudited() {
    loginWith("admin");
    RoleDto dto =
        service.setPermissions("viewer", Set.of(PermissionAction.ASK_AI, PermissionAction.MANAGE_ROLES));
    assertThat(viewer.getPermissions()).containsExactlyInAnyOrder("ASK_AI", "SEE_CAPTURES");
    assertThat(dto.getPermissions()).containsExactly(PermissionAction.SEE_CAPTURES, PermissionAction.ASK_AI);
    verify(audit)
        .record(eq("role.permissions.update"), eq("role"), eq("viewer"), any(Map.class), any(Map.class));
  }

  @Test
  void theAdminRoleCantBeChanged_norMadeTheDefault() {
    loginWith("admin");
    assertThatThrownBy(() -> service.setPermissions("admin", Set.of()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> service.setDefault("admin")).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void settingTheDefault_movesItFromTheOldRole() {
    loginWith("admin");
    service.setDefault("viewer");
    assertThat(viewer.isDefaultRole()).isTrue();
    assertThat(analyst.isDefaultRole()).isFalse();
    verify(audit).record(eq("role.default.set"), eq("role"), eq("viewer"), any(Map.class), any(Map.class));
  }

  @Test
  void deletingACapture_ownNeedsDeleteOwn_othersAndUnownedNeedDeleteAny() {
    loginWith("analyst");
    service.requireDeleteCapture("ana"); // own
    assertThatThrownBy(() -> service.requireDeleteCapture("bob"))
        .isInstanceOf(ForbiddenException.class)
        .hasMessageContaining("uploaded by bob");
    assertThatThrownBy(() -> service.requireDeleteCapture(null))
        .isInstanceOf(ForbiddenException.class)
        .hasMessageContaining("no recorded uploader");

    loginWith("lead");
    service.requireDeleteCapture("bob");
    service.requireDeleteCapture(null);
  }

  @Test
  void theCatalogue_listsEveryPermissionWithItsGroup_andWhetherICan() {
    loginWith("viewer");
    List<PermissionDto> all = service.list();
    assertThat(all).hasSize(PermissionAction.values().length);
    PermissionDto ai = all.stream().filter(p -> p.getAction() == PermissionAction.ASK_AI).findFirst().orElseThrow();
    assertThat(ai.getGroupLabel()).isEqualTo("Investigate");
    assertThat(ai.getSuggestedRole()).isEqualTo("analyst");
    assertThat(ai.isAllowed()).isFalse();
    assertThat(ai.getReason()).contains("Viewer");
  }

  private static RoleEntity role(String key, int position, boolean isDefault, PermissionAction... perms) {
    return RoleEntity.builder()
        .key(key)
        .label(key.substring(0, 1).toUpperCase() + key.substring(1))
        .builtIn(true)
        .position(position)
        .defaultRole(isDefault)
        .permissions(Arrays.stream(perms).map(Enum::name).collect(Collectors.toCollection(HashSet::new)))
        .updatedAt(LocalDateTime.now())
        .updatedBy("system")
        .build();
  }
}
