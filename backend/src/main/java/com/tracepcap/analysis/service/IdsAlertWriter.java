package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.IdsAlertEntity;
import com.tracepcap.analysis.repository.IdsAlertRepository;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists a file's Suricata alerts (#1265). Same contract as {@link WindowsLogonWriter}:
 * REQUIRES_NEW so a failure rolls back only this write, and the caller catches it, since the alert
 * records are supplementary to the conversations' own alert lists.
 */
@Service
@RequiredArgsConstructor
public class IdsAlertWriter {

  private final IdsAlertRepository repository;
  private final com.tracepcap.analysis.repository.SuricataAnomalyRepository anomalies;
  private final com.tracepcap.analysis.repository.CaptureStatsRepository stats;
  private final com.tracepcap.analysis.repository.RemoteOperationRepository remoteOperations;

  /** Regenerates this file's SMB and RPC operations (#1266). */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void replaceRemoteOperations(
      UUID fileId, List<com.tracepcap.analysis.entity.RemoteOperationEntity> rows) {
    remoteOperations.deleteByFileId(fileId);
    if (!rows.isEmpty()) remoteOperations.saveAll(rows);
  }

  /** Regenerates this file's alert records (#1265). */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void replaceAlerts(UUID fileId, List<IdsAlertEntity> alerts) {
    repository.deleteByFileId(fileId);
    if (!alerts.isEmpty()) repository.saveAll(alerts);
  }

  /** Regenerates this file's protocol anomalies (#1268). */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void replaceAnomalies(
      UUID fileId, List<com.tracepcap.analysis.entity.SuricataAnomalyEntity> anomalyRows) {
    anomalies.deleteByFileId(fileId);
    if (!anomalyRows.isEmpty()) anomalies.saveAll(anomalyRows);
  }

  /** Suricata's counters for this file's run (#1268), replacing any earlier ones. */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void saveStats(com.tracepcap.analysis.entity.CaptureStatsEntity row) {
    stats.save(row);
  }
}
