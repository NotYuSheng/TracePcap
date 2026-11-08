package com.tracepcap.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.config.security.CurrentActor;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** The #915 permission rules: analyst actions are open, admin actions and level changes aren't. */
class PermissionServiceTest {

  private final PermissionRepository repo = mock(PermissionRepository.class);
  private final CurrentActor actor = mock(CurrentActor.class);
  private final AuditLogService audit = mock(AuditLogService.class);
  private final PermissionService service = new PermissionService(repo, actor, audit);

  @Test
  void defaults_analystsForRulesAndSettings_adminForRetention() {
    when(repo.findById(anyString())).thenReturn(Optional.empty());
    assertThat(PermissionAction.NETWORK_SETTINGS.defaultLevel()).isEqualTo(PermissionLevel.ANALYST);
    assertThat(PermissionAction.DETECTION_RULES_GLOBAL.defaultLevel()).isEqualTo(PermissionLevel.ANALYST);
    assertThat(PermissionAction.RETENTION.defaultLevel()).isEqualTo(PermissionLevel.ADMIN);
    assertThat(service.can(PermissionAction.NETWORK_SETTINGS)).isTrue();
    assertThat(service.can(PermissionAction.RETENTION)).isFalse();
  }

  @Test
  void adminActionIsAllowedForAdmins_andRefusedWithTheReasonOtherwise() {
    when(repo.findById(anyString())).thenReturn(Optional.empty());
    when(actor.authEnabled()).thenReturn(false);
    assertThatThrownBy(() -> service.require(PermissionAction.RETENTION))
        .isInstanceOf(ForbiddenException.class)
        .hasMessageContaining("SYSTEM_SETTINGS_EDITABLE");
    when(actor.isAdmin()).thenReturn(true);
    service.require(PermissionAction.RETENTION);
  }

  @Test
  void anOverrideReplacesTheDefault() {
    when(repo.findById("NETWORK_SETTINGS")).thenReturn(Optional.of(row("NETWORK_SETTINGS", PermissionLevel.ADMIN)));
    when(actor.authEnabled()).thenReturn(true);
    assertThat(service.can(PermissionAction.NETWORK_SETTINGS)).isFalse();
    assertThatThrownBy(() -> service.require(PermissionAction.NETWORK_SETTINGS))
        .hasMessageContaining("Keycloak");
  }

  @Test
  void listShowsEveryActionWithAllowedAndReason() {
    when(repo.findAll()).thenReturn(List.of(row("ANALYSIS_POLICY", PermissionLevel.ADMIN)));
    List<PermissionDto> list = service.list();
    assertThat(list).hasSize(PermissionAction.values().length);
    PermissionDto policy =
        list.stream().filter(p -> p.getAction() == PermissionAction.ANALYSIS_POLICY).findFirst().orElseThrow();
    assertThat(policy.getLevel()).isEqualTo(PermissionLevel.ADMIN);
    assertThat(policy.getDefaultLevel()).isEqualTo(PermissionLevel.ANALYST);
    assertThat(policy.isAllowed()).isFalse();
    assertThat(policy.getReason()).isNotBlank();
  }

  @Test
  void changingALevelIsAdminOnly_andAudited() {
    when(repo.findById(anyString())).thenReturn(Optional.empty());
    assertThatThrownBy(() -> service.update(PermissionAction.NETWORK_SETTINGS, PermissionLevel.ADMIN))
        .isInstanceOf(ForbiddenException.class);
    verify(repo, never()).save(any());

    when(actor.isAdmin()).thenReturn(true);
    when(actor.username()).thenReturn("alice");
    PermissionDto dto = service.update(PermissionAction.NETWORK_SETTINGS, PermissionLevel.ADMIN);
    assertThat(dto.getLevel()).isEqualTo(PermissionLevel.ADMIN);
    verify(audit)
        .record(
            "permission.update",
            "permission",
            "NETWORK_SETTINGS",
            Map.of("level", PermissionLevel.ANALYST),
            Map.of("level", PermissionLevel.ADMIN));
  }

  private static PermissionEntity row(String action, PermissionLevel level) {
    return PermissionEntity.builder()
        .action(action)
        .level(level)
        .updatedAt(LocalDateTime.now())
        .updatedBy("x")
        .build();
  }
}
