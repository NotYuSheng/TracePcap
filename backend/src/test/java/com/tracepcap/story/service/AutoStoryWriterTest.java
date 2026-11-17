package com.tracepcap.story.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.common.aijob.AiJobService;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AutoStoryWriterTest {

  private final StoryService stories = mock(StoryService.class);
  private final FileRepository files = mock(FileRepository.class);
  private final AiJobService jobs = mock(AiJobService.class);
  private final AutoStoryWriter writer = new AutoStoryWriter(stories, files, jobs);

  private FileEntity file(UUID id, String name) {
    FileEntity f = new FileEntity();
    f.setId(id);
    f.setFileName(name);
    return f;
  }

  @Test
  void an_upload_story_joins_the_ai_job_line() {
    UUID id = UUID.randomUUID();
    when(files.findById(id)).thenReturn(Optional.of(file(id, "strrat.pcapng")));

    writer.write(id);

    verify(jobs).submit(eq("STORY"), eq(id), eq("strrat.pcapng"), eq("UPLOAD"), any());
  }

  @Test
  void a_deleted_capture_queues_nothing() {
    UUID id = UUID.randomUUID();
    when(files.findById(id)).thenReturn(Optional.empty());
    writer.write(id);
    verify(jobs, never()).submit(any(), any(), any(), any(), any());
  }

  @Test
  void after_a_restart_unfinished_upload_stories_are_queued_again() {
    UUID waiting = UUID.randomUUID();
    UUID writing = UUID.randomUUID();
    when(files.findByStatusAndStoryStatusIn(eq(FileEntity.FileStatus.COMPLETED), anyCollection()))
        .thenReturn(List.of(file(waiting, "a.pcap"), file(writing, "b.pcap")));
    when(files.findById(waiting)).thenReturn(Optional.of(file(waiting, "a.pcap")));
    when(files.findById(writing)).thenReturn(Optional.of(file(writing, "b.pcap")));

    writer.resumeAfterRestart();

    verify(files).updateStoryStatus(writing, FileEntity.STORY_QUEUED, null);
    verify(jobs).submit(eq("STORY"), eq(waiting), eq("a.pcap"), eq("UPLOAD"), any());
    verify(jobs).submit(eq("STORY"), eq(writing), eq("b.pcap"), eq("UPLOAD"), any());
  }
}
