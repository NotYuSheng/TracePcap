package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.ConversationDetailResponse;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.service.AnalysisService;
import com.tracepcap.common.dto.PagedResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** REST controller for conversation operations */
@Slf4j
@RestController
@RequestMapping("/api/conversations")
@RequiredArgsConstructor
public class ConversationsController {

  private final AnalysisService analysisService;

  /** Get conversations for a file with optional pagination */
  @GetMapping("/{fileId}")
  @Operation(summary = "Get conversations with pagination support")
  public ResponseEntity<PagedResponse<ConversationResponse>> getConversations(
      @PathVariable UUID fileId,
      @Parameter(description = "Page number (1-indexed)") @RequestParam(defaultValue = "1")
          int page,
      @Parameter(description = "Number of items per page") @RequestParam(defaultValue = "25")
          int pageSize,
      @Parameter(description = "Filter by app name, protocol, IP or hostname")
          @RequestParam(required = false) String search) {

    log.info("GET /api/conversations/{} - page: {}, pageSize: {}, search: {}", fileId, page, pageSize, search);

    // Validate pagination parameters
    if (page < 1) {
      page = 1;
    }
    if (pageSize < 1 || pageSize > 100) {
      pageSize = 25; // Default to 25 if invalid
    }

    List<ConversationResponse> allConversations = analysisService.getConversations(fileId, search);
    PagedResponse<ConversationResponse> pagedResponse =
        PagedResponse.of(allConversations, page, pageSize);

    return ResponseEntity.ok(pagedResponse);
  }

  /** Get detailed conversation info including all packets */
  @GetMapping("/detail/{conversationId}")
  @Operation(summary = "Get conversation details with packet stream")
  public ResponseEntity<ConversationDetailResponse> getConversationDetail(
      @PathVariable UUID conversationId) {
    log.info("GET /api/conversations/detail/{}", conversationId);
    ConversationDetailResponse detail = analysisService.getConversationDetail(conversationId);
    return ResponseEntity.ok(detail);
  }
}
