package com.tracepcap.story.controller;

import com.tracepcap.common.aijob.AiJobDto;
import com.tracepcap.common.aijob.AiJobService;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.story.dto.StoryJobRequest;
import com.tracepcap.story.service.AutoStoryWriter;
import com.tracepcap.story.service.StoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Writing a capture's story in the background: the page doesn't wait on the model. */
@RestController
@RequiredArgsConstructor
@Tag(name = "Story Generation", description = "APIs for AI-powered network traffic story generation")
public class StoryJobController {

  private final AiJobService jobs;
  private final StoryService stories;
  private final FileRepository files;

  @PostMapping("/files/{fileId}/story-jobs")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Write the story in the background",
      description = "Queues the story and returns at once with the job WAITING. Check on it at /ai-jobs/{id}: it ends DONE with the story as its result, or FAILED with why (CONTEXT_LENGTH_EXCEEDED carries the prompt to cut down). The current story stays until the new one is written. Asking again while one waits or runs returns that job.")
  public AiJobDto start(@PathVariable UUID fileId, @RequestBody(required = false) StoryJobRequest request) {
    FileEntity file =
        files.findById(fileId).orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));
    StoryJobRequest r = request != null ? request : new StoryJobRequest();
    return jobs.submit(
        AutoStoryWriter.JOB_KIND,
        fileId,
        file.getFileName(),
        () -> stories.generateStory(
            fileId, r.getAdditionalContext(), r.getCustomPrompt(), r.getMaxFindings(),
            r.getMaxRiskMatrix(), r.getNetworkId()));
  }
}
