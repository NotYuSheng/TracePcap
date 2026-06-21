package com.tracepcap.story.controller;

import com.tracepcap.story.dto.GenerateStoryRequest;
import com.tracepcap.story.dto.StoryAnswerResponse;
import com.tracepcap.story.dto.StoryQuestionRequest;
import com.tracepcap.story.dto.StoryResponse;
import com.tracepcap.story.service.StoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** REST controller for story generation and management */
@Slf4j
@RestController
@RequestMapping("/stories")
@RequiredArgsConstructor
@Tag(
    name = "Story Generation",
    description = "APIs for AI-powered network traffic story generation")
public class StoryController {

  private final StoryService storyService;

  @PostMapping
  @Operation(
      summary = "Generate story",
      description = "Generate an AI-powered narrative story for a PCAP file")
  public ResponseEntity<StoryResponse> generateStory(
      @Valid @RequestBody GenerateStoryRequest request) {
    UUID fileId = request.getFileId();
    log.info("Received story generation request for file: {}", fileId);

    StoryResponse story =
        storyService.generateStory(
            fileId,
            request.getAdditionalContext(),
            request.getCustomPrompt(),
            request.getMaxFindings(),
            request.getMaxRiskMatrix());

    return ResponseEntity.status(HttpStatus.CREATED).body(story);
  }

  @GetMapping("/{storyId}")
  @Operation(summary = "Get story", description = "Get a generated story by ID")
  public ResponseEntity<StoryResponse> getStory(@PathVariable String storyId) {
    log.info("Fetching story: {}", storyId);

    StoryResponse story = storyService.getStory(UUID.fromString(storyId));

    return ResponseEntity.ok(story);
  }

  @PostMapping("/{storyId}/questions")
  @Operation(
      summary = "Ask a question",
      description = "Ask the LLM a question about an existing story")
  public ResponseEntity<StoryAnswerResponse> askQuestion(
      @PathVariable UUID storyId, @RequestBody StoryQuestionRequest request) {
    log.info("Received question for story: {}", storyId);

    StoryAnswerResponse answer =
        storyService.askQuestion(storyId, request.getQuestion(), request.getHistory());

    return ResponseEntity.ok(answer);
  }

  @GetMapping
  @Operation(
      summary = "Get story by file",
      description = "Get the latest story for a file, if one exists")
  public ResponseEntity<StoryResponse> getStoryByFileId(@RequestParam UUID fileId) {
    log.info("Fetching latest story for file: {}", fileId);

    Optional<StoryResponse> story = storyService.getStoryByFileId(fileId);

    return story.map(ResponseEntity::ok).orElse(ResponseEntity.noContent().build());
  }
}
