package com.tracepcap.tracer.controller;

import com.tracepcap.governance.PermissionService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.common.aijob.AiJobDto;
import com.tracepcap.common.aijob.AiJobService;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.tracer.service.ConversationTracerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.NoSuchElementException;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Explaining a conversation's packets with AI in the background. */
@RestController
@RequiredArgsConstructor
@Tag(name = "Conversation Tracer", description = "Packet-level conversation trace with AI explanations")
public class ExplanationJobController {

  public static final String KIND = "TRACE_EXPLANATIONS";

  private final PermissionService permissionService;

  private final AiJobService jobs;
  private final ConversationTracerService tracer;

  @PostMapping("/tracer/{conversationId}/explanation-jobs")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Explain each packet in the background",
      description = "Returns at once with a job. Explanations already worked out (they're kept per conversation), or a conversation with no packets, come back DONE straight away; otherwise the job waits its turn for the model. Check on it at /ai-jobs/{id}: DONE carries the explanations, or an error saying why the model couldn't give them.")
  public AiJobDto start(@PathVariable UUID conversationId) {
    permissionService.require(PermissionAction.ASK_AI);
    ConversationTracerService.Prepared p;
    try {
      p = tracer.prepareExplanations(conversationId);
    } catch (NoSuchElementException e) {
      throw new ResourceNotFoundException(e.getMessage());
    }
    String key = conversationId.toString();
    return p.ready() != null
        ? jobs.finished(KIND, null, key, p.name(), p.ready())
        : jobs.submitFor(KIND, null, key, p.name(), p.ask());
  }
}
