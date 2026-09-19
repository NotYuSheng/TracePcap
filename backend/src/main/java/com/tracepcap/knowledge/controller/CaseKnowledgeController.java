package com.tracepcap.knowledge.controller;

import com.tracepcap.knowledge.dto.AnswerResponse;
import com.tracepcap.knowledge.dto.CaseKnowledgeResponse;
import com.tracepcap.knowledge.service.CaseKnowledgeService;
import com.tracepcap.knowledge.service.StandardQuestionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Read surface for the assembled per-file knowledge board (#813). */
@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(
    name = "Knowledge",
    description = "The assembled knowledge board for a file — entities, relationships, and findings")
public class CaseKnowledgeController {

  private final CaseKnowledgeService caseKnowledgeService;
  private final StandardQuestionService standardQuestionService;

  @GetMapping("/{fileId}/knowledge")
  @Operation(summary = "Assembled knowledge board (entities, relationships, findings) for a file")
  public ResponseEntity<CaseKnowledgeResponse> getKnowledge(@PathVariable UUID fileId) {
    return ResponseEntity.ok(CaseKnowledgeResponse.from(caseKnowledgeService.assemble(fileId)));
  }

  @GetMapping("/{fileId}/answers")
  @Operation(summary = "Deterministic answers to the standard investigation questions for a file")
  public ResponseEntity<List<AnswerResponse>> getAnswers(@PathVariable UUID fileId) {
    return ResponseEntity.ok(
        standardQuestionService.answer(fileId).stream().map(AnswerResponse::from).toList());
  }
}
