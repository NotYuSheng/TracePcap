package com.tracepcap.tracer.controller;

import com.tracepcap.tracer.dto.TracerExplainResponse;
import com.tracepcap.tracer.dto.TracerPeersResponse;
import com.tracepcap.tracer.dto.TracerStepsResponse;
import com.tracepcap.tracer.service.ConversationTracerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/tracer")
@RequiredArgsConstructor
@Tag(name = "Conversation Tracer", description = "Packet-level conversation trace with AI explanations")
public class ConversationTracerController {

  private final ConversationTracerService tracerService;

  @GetMapping("/{conversationId}/steps")
  @Operation(
      summary = "Get conversation steps",
      description = "Returns ordered packet steps for a conversation, ready for step-through visualisation.")
  public ResponseEntity<TracerStepsResponse> getSteps(@PathVariable UUID conversationId) {
    log.info("GET /api/tracer/{}/steps", conversationId);
    return ResponseEntity.ok(tracerService.getSteps(conversationId));
  }

  @GetMapping("/{conversationId}/peers")
  @Operation(
      summary = "Get traced host's peers with response status",
      description = "Returns every peer the traced host exchanged packets with, each flagged as responding or silent — for scan-style visualisation (e.g. ARP scans).")
  public ResponseEntity<TracerPeersResponse> getPeers(@PathVariable UUID conversationId) {
    log.info("GET /api/tracer/{}/peers", conversationId);
    return ResponseEntity.ok(tracerService.getPeers(conversationId));
  }

  @PostMapping("/{conversationId}/explain")
  @Operation(
      summary = "Generate AI explanations",
      description = "Generates a plain-English explanation for each packet in the conversation using the configured LLM. Results are cached per conversation.")
  public ResponseEntity<TracerExplainResponse> explainSteps(@PathVariable UUID conversationId) {
    log.info("POST /api/tracer/{}/explain", conversationId);
    TracerExplainResponse response = tracerService.explainSteps(conversationId);
    if (response.getError() != null) {
      return ResponseEntity.status(503).body(response);
    }
    return ResponseEntity.ok(response);
  }
}
