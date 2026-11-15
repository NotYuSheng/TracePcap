package com.tracepcap.story.service;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;

import com.tracepcap.common.event.AnalysisCompletedEvent;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The background story starts only for an upload that asked for one, and only once. */
class AutoStoryListenerTest {

  private final FileRepository files = mock(FileRepository.class);
  private final AutoStoryWriter writer = mock(AutoStoryWriter.class);
  private final AutoStoryListener listener = new AutoStoryListener(files, writer);
  private final UUID id = UUID.randomUUID();

  private void file(boolean generateStory, String status) {
    when(files.findById(id))
        .thenReturn(
            Optional.of(
                FileEntity.builder().id(id).generateStory(generateStory).storyStatus(status).build()));
  }

  @Test
  void startsAQueuedStory() {
    file(true, FileEntity.STORY_QUEUED);
    listener.onAnalysisCompleted(new AnalysisCompletedEvent(id));
    verify(writer).write(id);
  }

  @Test
  void leavesAFileThatDidNotAskAlone() {
    file(false, null);
    listener.onAnalysisCompleted(new AnalysisCompletedEvent(id));
    verify(writer, never()).write(any());
  }

  @Test
  void doesNotWriteItAgainOnReanalysis() {
    file(true, FileEntity.STORY_READY);
    listener.onAnalysisCompleted(new AnalysisCompletedEvent(id));
    verify(writer, never()).write(any());
  }
}
