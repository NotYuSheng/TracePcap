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

  /** Regenerates this file's alerts and protocol anomalies (#1268). */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void replaceForFile(
      UUID fileId,
      List<IdsAlertEntity> alerts,
      List<com.tracepcap.analysis.entity.SuricataAnomalyEntity> anomalyRows) {
    repository.deleteByFileId(fileId);
    if (!alerts.isEmpty()) repository.saveAll(alerts);
    anomalies.deleteByFileId(fileId);
    if (!anomalyRows.isEmpty()) anomalies.saveAll(anomalyRows);
  }

  /** Suricata's counters for this file's run (#1268), replacing any earlier ones. */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void saveStats(com.tracepcap.analysis.entity.CaptureStatsEntity row) {
    stats.save(row);
  }
}
