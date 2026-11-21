package com.tracepcap.governance;

import com.tracepcap.common.aijob.AiJobCancelGate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Cancelling someone else's AI work follows the roles model. */
@Component
@RequiredArgsConstructor
class AiJobCancelGateImpl implements AiJobCancelGate {

  private final PermissionService permissionService;

  @Override
  public boolean mayCancelOthers() {
    return permissionService.can(PermissionAction.CANCEL_OTHERS_AI_JOBS);
  }
}
