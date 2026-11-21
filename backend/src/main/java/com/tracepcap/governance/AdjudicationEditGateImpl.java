package com.tracepcap.governance;

import com.tracepcap.common.adjudication.AdjudicationEditGate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Overriding an answer follows the roles model. */
@Component
@RequiredArgsConstructor
class AdjudicationEditGateImpl implements AdjudicationEditGate {

  private final PermissionService permissionService;

  @Override
  public void requireEdit() {
    permissionService.require(PermissionAction.OVERRIDE_ANSWERS);
  }
}
