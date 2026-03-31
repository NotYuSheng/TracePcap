package com.tracepcap.story.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;

/** Response body for a story Q&A answer */
@Data
@AllArgsConstructor
public class StoryAnswerResponse {
  private String answer;
  private List<String> followUpQuestions;
}
