package com.tracepcap.signatures.service;

import com.tracepcap.file.event.FileVersionCreatedEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * A re-analysis version (#915 phase 3) starts with its original's own detection rules. Runs
 * synchronously in the transaction that creates the version, before its analysis is triggered
 * (after commit), so the analysis applies them.
 */
@Component
@RequiredArgsConstructor
class FileVersionListener {

  private final DetectionRuleService rules;

  @EventListener
  public void onVersionCreated(FileVersionCreatedEvent e) {
    rules.copyCaptureRules(e.getFromId(), e.getVersionId());
  }
}
