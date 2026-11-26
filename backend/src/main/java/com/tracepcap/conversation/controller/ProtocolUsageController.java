package com.tracepcap.conversation.controller;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.conversation.dto.ProtocolCaptureDto;
import com.tracepcap.conversation.dto.ProtocolUsageDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Which protocols your captures contain, for the protocol reference ("seen in your captures"). */
@RestController
@RequestMapping("/protocol-usage")
@RequiredArgsConstructor
@Tag(name = "Protocol usage", description = "Which nDPI protocols appear in your captures, and where")
public class ProtocolUsageController {

  private static final int MAX_CAPTURES = 200;

  private final ConversationLookup conversations;

  @GetMapping
  @Operation(
      summary = "Every nDPI application name in your captures, with how many captures and conversations",
      description = "Counts original captures only; a re-analysis is a copy of one.")
  public List<ProtocolUsageDto> usage() {
    return conversations.appUsage().stream()
        .map(u -> new ProtocolUsageDto(u.appName(), u.captures(), u.conversations()))
        .toList();
  }

  @GetMapping("/{appName}/captures")
  @Operation(summary = "The captures an nDPI application name appears in, most conversations first")
  public List<ProtocolCaptureDto> captures(
      @PathVariable String appName, @RequestParam(defaultValue = "20") int limit) {
    int lim = Math.max(1, Math.min(limit, MAX_CAPTURES));
    return conversations.appCaptures(appName, lim).stream()
        .map(c -> new ProtocolCaptureDto(c.fileId(), c.fileName(), c.conversations()))
        .toList();
  }
}
