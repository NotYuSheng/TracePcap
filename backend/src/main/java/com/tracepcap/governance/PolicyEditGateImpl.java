package com.tracepcap.governance;

import com.tracepcap.common.settings.EditablePolicy;
import com.tracepcap.common.settings.PolicyEditGate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Editable policy follows the permissions model (#915): retention and analysis policy. */
@Component
@RequiredArgsConstructor
class PolicyEditGateImpl implements PolicyEditGate {

  private final PermissionService permissionService;

  static PermissionAction actionFor(EditablePolicy.Kind kind) {
    return kind == EditablePolicy.Kind.RETENTION
        ? PermissionAction.RETENTION
        : PermissionAction.ANALYSIS_POLICY;
  }

  @Override
  public boolean canEdit(EditablePolicy.Kind kind) {
    return permissionService.can(actionFor(kind));
  }

  @Override
  public String reason(EditablePolicy.Kind kind) {
    return permissionService.reason(actionFor(kind));
  }
}
