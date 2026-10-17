package com.tracepcap.knowledge.service;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Runs the deterministic {@link StandardQuestion} catalog against a file's assembled board and
 * collects the answers (#813). Questions are auto-discovered, so the catalog grows by adding a
 * class. Each question is isolated: one that throws is logged and skipped.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class StandardQuestionService {

  private final CaseKnowledgeService caseKnowledgeService;
  private final List<StandardQuestion> questions;

  /** Assembles the board and returns every answer the catalog can support for it. */
  public List<Answer> answer(UUID fileId) {
    CaseKnowledge board = caseKnowledgeService.assemble(fileId);
    return answer(board);
  }

  /** Runs the catalog against an already-assembled board (the unit-testable seam). */
  public List<Answer> answer(CaseKnowledge board) {
    List<Answer> answers = new ArrayList<>();
    for (StandardQuestion question : questions) {
      try {
        answers.addAll(question.answer(board));
      } catch (Exception e) {
        log.warn("Standard question '{}' failed for file {}: {}",
            question.question(), board.fileId(), e.getMessage());
      }
    }
    log.info("Answered {} standard question result(s) for file {} from {} question(s)",
        answers.size(), board.fileId(), questions.size());
    return answers;
  }
}
