package com.tracepcap.signatures.service;

import com.tracepcap.monitor.event.SnapshotMembershipChangedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Keeps network-rule results in step with network membership (#925 phase 3): a capture that joins
 * a network is checked against its rules; one that leaves loses that network's results. Runs after
 * the membership change commits, in its own transaction, and never fails the change itself.
 */
@Slf4j
@Component
@RequiredArgsConstructor
class NetworkMembershipListener {

  private final RuleSyncService ruleSync;

  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onMembershipChanged(SnapshotMembershipChangedEvent e) {
    try {
      if (e.added()) ruleSync.onJoinedNetwork(e.networkId(), e.fileId());
      else ruleSync.onLeftNetwork(e.networkId(), e.fileId());
    } catch (Exception ex) {
      // The capture is still in (or out of) the network; its network-rule results will show as
      // out of date, and Re-apply fixes them.
      log.warn(
          "Couldn't update network {} rule results for capture {}: {}", e.networkId(), e.fileId(), ex.getMessage());
    }
  }
}
