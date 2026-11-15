package com.tracepcap.governance;

import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.common.settings.EditablePolicy;
import com.tracepcap.common.settings.RuntimePolicy;
import com.tracepcap.common.settings.SystemSettingOverrideEntity;
import com.tracepcap.common.settings.SystemSettingOverrideRepository;
import com.tracepcap.config.security.CurrentActor;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Changes editable analysis policy in the app (#915 phase 5): permission-checked per kind,
 * validated, and audited with before and after.
 */
@Service
@RequiredArgsConstructor
public class PolicySettingsService {

  static final String AUDIT_TARGET = "system-setting";

  private final SystemSettingOverrideRepository repository;
  private final RuntimePolicy runtimePolicy;
  private final PermissionService permissionService;
  private final AuditLogService auditLog;
  private final CurrentActor currentActor;

  /** Overrides a setting with {@code rawValue}. Setting it to the deployment's value resets it. */
  @Transactional
  public void set(String key, String rawValue) {
    EditablePolicy p = editable(key);
    permissionService.require(PolicyEditGateImpl.actionFor(p.kind()));
    String value = p.normalise(rawValue);
    String before = runtimePolicy.value(p);
    boolean wasOverridden = runtimePolicy.isOverridden(p);
    if (value.equals(normalisedDeployValue(p))) {
      if (wasOverridden) {
        repository.deleteById(key);
        audit(key, before, wasOverridden, value, false);
      }
      return;
    }
    repository.save(
        SystemSettingOverrideEntity.builder()
            .key(key)
            .value(value)
            .updatedAt(LocalDateTime.now())
            .updatedBy(currentActor.username())
            .build());
    if (!value.equals(before) || !wasOverridden) audit(key, before, wasOverridden, value, true);
  }

  /** Removes the override, so the deployment's value applies again. */
  @Transactional
  public void reset(String key) {
    EditablePolicy p = editable(key);
    permissionService.require(PolicyEditGateImpl.actionFor(p.kind()));
    if (!runtimePolicy.isOverridden(p)) return;
    String before = runtimePolicy.value(p);
    repository.deleteById(key);
    audit(key, before, true, runtimePolicy.deployValue(p), false);
  }

  private void audit(String key, String before, boolean beforeOverridden, String after, boolean afterOverridden) {
    auditLog.record(
        "system-setting.update",
        AUDIT_TARGET,
        key,
        Map.of("value", before, "overridden", beforeOverridden),
        Map.of("value", after, "overridden", afterOverridden));
    // Clear the cache once the change is visible to other transactions, not before.
    if (TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.registerSynchronization(
          new TransactionSynchronization() {
            @Override
            public void afterCommit() {
              runtimePolicy.invalidate();
            }
          });
    } else {
      runtimePolicy.invalidate();
    }
  }

  /** The deployment's value in the same form, or null if it's outside what the app accepts. */
  private String normalisedDeployValue(EditablePolicy p) {
    try {
      return p.normalise(runtimePolicy.deployValue(p));
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private static EditablePolicy editable(String key) {
    return EditablePolicy.of(key)
        .orElseThrow(
            () ->
                new ResourceNotFoundException(
                    key + " can't be changed in the app; it's set when TracePcap is deployed."));
  }
}
