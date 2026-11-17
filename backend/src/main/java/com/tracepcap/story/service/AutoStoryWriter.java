package com.tracepcap.story.service;

import com.tracepcap.common.aijob.AiJobService;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

/**
 * Writes a capture's story in the background, as asked for at upload. It joins the same line as
 * every other AI job ({@link AiJobService}), so a batch of uploads writes its stories one after
 * another, and a story someone asks for on the Story tab waits its turn behind them.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AutoStoryWriter {

  /** The AI job kind for a story, whoever asked for it. */
  public static final String JOB_KIND = "STORY";

  private final StoryService storyService;
  private final FileRepository fileRepository;
  private final AiJobService jobs;

  /**
   * Jobs live in memory, so a restart drops a story that was waiting or being written. Once the
   * app is up, queue again every analysed capture whose upload-time story never finished.
   */
  @EventListener(ApplicationReadyEvent.class)
  public void resumeAfterRestart() {
    var unfinished =
        fileRepository.findByStatusAndStoryStatusIn(
            FileEntity.FileStatus.COMPLETED, List.of(FileEntity.STORY_QUEUED, FileEntity.STORY_WRITING));
    for (FileEntity f : unfinished) {
      fileRepository.updateStoryStatus(f.getId(), FileEntity.STORY_QUEUED, null);
      write(f.getId());
    }
    if (!unfinished.isEmpty()) log.info("Queued {} background stories again after a restart", unfinished.size());
  }

  public void write(UUID fileId) {
    FileEntity file = fileRepository.findById(fileId).orElse(null);
    if (file == null) return;
    jobs.submit(JOB_KIND, fileId, file.getFileName(), "UPLOAD", () -> run(fileId));
  }

  private Object run(UUID fileId) {
    // The file may have been deleted while the story waited its turn.
    if (fileRepository.findById(fileId).isEmpty()) return null;
    fileRepository.updateStoryStatus(fileId, FileEntity.STORY_WRITING, null);
    try {
      Object story = storyService.generateStory(fileId, null);
      fileRepository.updateStoryStatus(fileId, FileEntity.STORY_READY, null);
      log.info("Background story written for file {}", fileId);
      return story;
    } catch (RuntimeException e) {
      log.warn("Background story failed for file {}: {}", fileId, e.getMessage());
      String reason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
      fileRepository.updateStoryStatus(fileId, FileEntity.STORY_FAILED, reason);
      throw e;
    }
  }
}
