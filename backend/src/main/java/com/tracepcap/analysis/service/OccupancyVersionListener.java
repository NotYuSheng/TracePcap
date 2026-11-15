package com.tracepcap.analysis.service;

import com.tracepcap.file.event.FileVersionCreatedEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * A re-analysis version (#951) starts with its original's split and merge decisions (#918). Runs
 * in the transaction that creates the version, before its analysis, so the analysis applies them.
 */
@Component
@RequiredArgsConstructor
class OccupancyVersionListener {

  private final HostOccupancyService occupancy;

  @EventListener
  public void onVersionCreated(FileVersionCreatedEvent e) {
    occupancy.copyDecisions(e.getFromId(), e.getVersionId());
  }
}
