package com.tracepcap.story.chat.dto;

import java.util.List;
import lombok.Value;

/** What the capture chat can look up, and whether the configured LLM takes tools. */
@Value
public class ChatToolsResponse {
  List<ChatToolDto> tools;
  /** "on", "off", or for the auto setting: "supported", "unsupported" or "unknown" (not tried yet). */
  String toolCalling;

  @Value
  public static class ChatToolDto {
    String name;
    String label;
    String summary;
    String example;
  }
}
