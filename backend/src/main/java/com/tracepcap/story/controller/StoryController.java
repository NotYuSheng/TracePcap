package com.tracepcap.story.controller;

import com.tracepcap.story.dto.StoryResponse;
import com.tracepcap.story.service.StoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST controller for story generation and management
 */
@Slf4j
@RestController
@RequestMapping("/api/story")
@RequiredArgsConstructor
@Tag(name = "Story Generation", description = "APIs for AI-powered network traffic story generation")
public class StoryController {

    private final StoryService storyService;

    @PostMapping("/generate/{fileId}")
    @Operation(summary = "Generate story", description = "Generate an AI-powered narrative story for a PCAP file")
    public ResponseEntity<StoryResponse> generateStory(@PathVariable String fileId) {
        log.info("Received story generation request for file: {}", fileId);

        StoryResponse story = storyService.generateStory(UUID.fromString(fileId));

        return ResponseEntity.status(HttpStatus.CREATED).body(story);
    }

    @GetMapping("/{storyId}")
    @Operation(summary = "Get story", description = "Get a generated story by ID")
    public ResponseEntity<StoryResponse> getStory(@PathVariable String storyId) {
        log.info("Fetching story: {}", storyId);

        StoryResponse story = storyService.getStory(UUID.fromString(storyId));

        return ResponseEntity.ok(story);
    }
}
