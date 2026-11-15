package com.tracepcap.story.service;

import com.tracepcap.common.event.AnalysisCompletedEvent;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Starts the background story once a capture's analysis has committed, when the upload asked for
 * one. Only a story still QUEUED is started, so a re-analysis doesn't write it again.
 */
@Component
@RequiredArgsConstructor
public class AutoStoryListener {

  private final FileRepository fileRepository;
  private final AutoStoryWriter writer;

  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
  public void onAnalysisCompleted(AnalysisCompletedEvent e) {
    fileRepository
        .findById(e.fileId())
        .filter(FileEntity::isGenerateStory)
        .filter(f -> FileEntity.STORY_QUEUED.equals(f.getStoryStatus()))
        .ifPresent(f -> writer.write(f.getId()));
  }
}
