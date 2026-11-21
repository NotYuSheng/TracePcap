package com.tracepcap.story.controller;

import com.tracepcap.governance.PermissionService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.story.chat.CaptureChatService;
import com.tracepcap.story.chat.dto.ChatToolsResponse;
import com.tracepcap.story.chat.dto.ChatTurnDto;
import com.tracepcap.story.chat.dto.ChatTurnRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The capture chat: questions the LLM answers, looking things up with tools (#1161). */
@RestController
@RequiredArgsConstructor
@Tag(name = "Capture chat", description = "Ask about a capture; the LLM may call read-only tools to look things up")
public class CaptureChatController {

  private final PermissionService permissionService;

  private final CaptureChatService chat;

  @GetMapping("/chat-tools")
  @Operation(
      summary = "What the capture chat can look up",
      description = "Each tool with its label, what it looks up and an example question, and whether the configured LLM takes tools.")
  public ChatToolsResponse tools() {
    return chat.tools();
  }

  @PostMapping("/files/{fileId}/chat-turns")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Ask a question about a capture",
      description = "Starts answering and returns at once with the turn RUNNING. Poll the turn: its steps grow as tools run, and it ends DONE with the answer or FAILED with the error.")
  public ChatTurnDto ask(@PathVariable UUID fileId, @Valid @RequestBody ChatTurnRequest request) {
    permissionService.require(PermissionAction.ASK_AI);
    return chat.start(fileId, request);
  }

  @GetMapping("/files/{fileId}/chat-turns/{turnId}")
  @Operation(
      summary = "One question's progress or answer",
      description = "The tool steps so far, and the answer, follow-up questions and checked filters once done. Turns are kept for 30 minutes.")
  public ChatTurnDto turn(@PathVariable UUID fileId, @PathVariable UUID turnId) {
    return chat.get(fileId, turnId);
  }
}
