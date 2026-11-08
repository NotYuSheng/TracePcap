package com.tracepcap.governance;

import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.config.security.CurrentActor;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Decides who may perform each configurable action (#915), and lets an admin change that.
 *
 * <p>An ANALYST action is open to anyone using the app. An ADMIN action needs {@link
 * CurrentActor#isAdmin()}: the Keycloak client role with login on, or {@code
 * SYSTEM_SETTINGS_EDITABLE} with login off.
 */
@Service
@RequiredArgsConstructor
public class PermissionService {

  static final String AUDIT_TARGET = "permission";

  private final PermissionRepository repository;
  private final CurrentActor currentActor;
  private final AuditLogService auditLog;

  @Transactional(readOnly = true)
  public PermissionLevel level(PermissionAction action) {
    return repository
        .findById(action.name())
        .map(PermissionEntity::getLevel)
        .orElse(action.defaultLevel());
  }

  @Transactional(readOnly = true)
  public boolean can(PermissionAction action) {
    return allowed(level(action));
  }

  /** Throws a 403 with the reason unless the caller may perform {@code action}. */
  @Transactional(readOnly = true)
  public void require(PermissionAction action) {
    PermissionLevel level = level(action);
    if (!allowed(level)) throw new ForbiddenException(action.label() + ": " + reasonFor(level));
  }

  /** Every configurable action, as it applies to the caller. */
  @Transactional(readOnly = true)
  public List<PermissionDto> list() {
    Map<String, PermissionLevel> overrides =
        repository.findAll().stream()
            .collect(Collectors.toMap(PermissionEntity::getAction, PermissionEntity::getLevel));
    return Arrays.stream(PermissionAction.values())
        .map(a -> toDto(a, overrides.getOrDefault(a.name(), a.defaultLevel())))
        .toList();
  }

  /** Whether the caller may change the levels themselves. Always admin-only. */
  public boolean canManage() {
    return currentActor.isAdmin();
  }

  /** The reason the caller can't change levels, or null when they can. */
  public String manageReason() {
    return canManage() ? null : reasonFor(PermissionLevel.ADMIN);
  }

  /** Sets the level an action requires. Admin-only, audited. */
  @Transactional
  public PermissionDto update(PermissionAction action, PermissionLevel newLevel) {
    if (!canManage()) {
      throw new ForbiddenException("Changing permissions: " + manageReason());
    }
    PermissionLevel before = level(action);
    repository.save(
        PermissionEntity.builder()
            .action(action.name())
            .level(newLevel)
            .updatedAt(LocalDateTime.now())
            .updatedBy(currentActor.username())
            .build());
    if (before != newLevel) {
      auditLog.record(
          "permission.update", AUDIT_TARGET, action.name(), Map.of("level", before), Map.of("level", newLevel));
    }
    return toDto(action, newLevel);
  }

  private boolean allowed(PermissionLevel level) {
    return level == PermissionLevel.ANALYST || currentActor.isAdmin();
  }

  private String reasonFor(PermissionLevel level) {
    if (level == PermissionLevel.ANALYST) return null;
    return currentActor.authEnabled()
        ? "only admins can change this. Ask an admin, or for the admin role in Keycloak."
        : "only admins can change this, and with login off that needs"
            + " SYSTEM_SETTINGS_EDITABLE=true on the server.";
  }

  private PermissionDto toDto(PermissionAction a, PermissionLevel level) {
    boolean allowed = allowed(level);
    return PermissionDto.builder()
        .action(a)
        .label(a.label())
        .description(a.description())
        .level(level)
        .defaultLevel(a.defaultLevel())
        .allowed(allowed)
        .reason(allowed ? null : reasonFor(level))
        .build();
  }

}
