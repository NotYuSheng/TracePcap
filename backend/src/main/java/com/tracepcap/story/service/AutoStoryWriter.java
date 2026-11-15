package com.tracepcap.story.service;

import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Writes a capture's story in the background, as asked for at upload. Runs on the single-thread
 * {@code storyExecutor}: a batch of uploads queues its stories one after another instead of
 * sending them all to the local model at once.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AutoStoryWriter {

  private final StoryService storyService;
  private final FileRepository fileRepository;

  @Async("storyExecutor")
  public void write(UUID fileId) {
    // The file may have been deleted while the story waited its turn.
    if (fileRepository.findById(fileId).isEmpty()) return;
    fileRepository.updateStoryStatus(fileId, FileEntity.STORY_WRITING, null);
    try {
      storyService.generateStory(fileId, null);
      fileRepository.updateStoryStatus(fileId, FileEntity.STORY_READY, null);
      log.info("Background story written for file {}", fileId);
    } catch (Exception e) {
      log.warn("Background story failed for file {}: {}", fileId, e.getMessage());
      String reason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
      fileRepository.updateStoryStatus(fileId, FileEntity.STORY_FAILED, reason);
    }
  }
}
