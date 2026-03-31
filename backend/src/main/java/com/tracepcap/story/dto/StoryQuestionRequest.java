package com.tracepcap.story.dto;

import java.util.List;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Request body for asking a question about a story */
@Data
@NoArgsConstructor
public class StoryQuestionRequest {
  private String question;
  private List<HistoryEntry> history;

  @Data
  @NoArgsConstructor
  public static class HistoryEntry {
    private String role; // "user" or "assistant"
    private String text;
  }
}
