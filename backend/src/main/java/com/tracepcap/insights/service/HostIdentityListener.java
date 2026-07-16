package com.tracepcap.insights.service;

import com.tracepcap.common.event.AnalysisCompletedEvent;
import com.tracepcap.common.event.NodeRoleChangedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Triggers host-identity adjudication (#512 slice 5). Two entry points, both AFTER_COMMIT in a
 * fresh transaction so an adjudication failure never rolls back the pipeline or a user's label:
 * analysis completion (fresh facts) and node-role change (a human label is the top-ranked input,
 * so its change re-opens the question — staleness IS re-adjudication).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HostIdentityListener {

  private final HostIdentityService hostIdentityService;

  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void onAnalysisCompleted(AnalysisCompletedEvent event) {
    adjudicate(event.fileId(), "analysis completion");
  }

  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void onNodeRoleChanged(NodeRoleChangedEvent event) {
    adjudicate(event.fileId(), "node-role change");
  }

  private void adjudicate(java.util.UUID fileId, String trigger) {
    try {
      hostIdentityService.adjudicateFile(fileId);
    } catch (Exception e) {
      log.error("Host-identity adjudication failed for file {} ({}): {}", fileId, trigger, e.getMessage(), e);
    }
  }
}
