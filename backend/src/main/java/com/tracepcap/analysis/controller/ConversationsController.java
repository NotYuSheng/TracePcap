package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.service.AnalysisService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST controller for conversation operations
 */
@Slf4j
@RestController
@RequestMapping("/api/conversations")
@RequiredArgsConstructor
public class ConversationsController {

    private final AnalysisService analysisService;

    /**
     * Get all conversations for a file
     */
    @GetMapping("/{fileId}")
    public ResponseEntity<List<ConversationResponse>> getConversations(@PathVariable UUID fileId) {
        log.info("GET /api/conversations/{}", fileId);
        List<ConversationResponse> conversations = analysisService.getConversations(fileId);
        return ResponseEntity.ok(conversations);
    }
}
