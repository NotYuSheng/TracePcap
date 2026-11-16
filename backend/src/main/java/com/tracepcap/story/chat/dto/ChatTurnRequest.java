package com.tracepcap.story.chat.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.UUID;
import lombok.Data;

/** A question for the capture chat, with the conversation so far. */
@Data
public class ChatTurnRequest {
  @NotBlank
  @Size(max = 4000)
  private String question;

  /** Earlier questions and answers, oldest first. */
  @Valid
  @Size(max = 40)
  private List<HistoryEntry> history;

  /** Read with this network's detection rules (#925); null for the shared rules. */
  private UUID networkId;

  @Data
  public static class HistoryEntry {
    /** "user" or "assistant". */
    @NotBlank private String role;

    @NotBlank
    @Size(max = 8000)
    private String text;
  }
}
