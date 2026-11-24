package com.tracepcap.knowledge.dto;

import com.tracepcap.knowledge.dto.CaseKnowledgeResponse.EntityRefDto;
import com.tracepcap.knowledge.spi.Answer;
import java.util.List;
import java.util.Map;

/** API view of a deterministic standard-question answer (#813). */
public record AnswerResponse(
    String question,
    String headline,
    String grade,
    List<EntityRefDto> subjects,
    List<String> basis,
    Map<String, Object> attributes,
    List<StepResponse> derivation) {

  /**
   * One step in how the answer was reached (#1293): what was found, the rule applied to it (null
   * for context), its grade, and the conversations it rests on.
   */
  public record StepResponse(String found, String rule, String grade, List<String> conversations) {}

  public static AnswerResponse from(Answer a) {
    return new AnswerResponse(
        a.question(),
        a.headline(),
        a.grade().name(),
        a.subjects().stream().map(EntityRefDto::from).toList(),
        a.basis(),
        a.attributes(),
        a.derivation().stream()
            .map(s -> new StepResponse(s.found(), s.rule(), s.grade().name(), s.conversations()))
            .toList());
  }
}
