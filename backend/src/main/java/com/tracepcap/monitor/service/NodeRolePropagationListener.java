package com.tracepcap.monitor.service;

import com.tracepcap.common.event.NodeRoleChangedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Carries a node-role change forward across its network chain once the change has committed (#369).
 * Runs after commit in a new transaction so a propagation failure never rolls back the user's label,
 * and so the carried rows/events are computed against the persisted role.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class NodeRolePropagationListener {

  private final ChangeDetectionService changeDetectionService;

  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void onNodeRoleChanged(NodeRoleChangedEvent event) {
    try {
      changeDetectionService.propagateRoleChange(event.fileId());
    } catch (Exception e) {
      log.error("Failed to propagate role change for file {}: {}", event.fileId(), e.getMessage(), e);
    }
  }
}
