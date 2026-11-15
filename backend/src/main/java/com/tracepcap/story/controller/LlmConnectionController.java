package com.tracepcap.story.controller;

import com.tracepcap.story.dto.LlmTestRequest;
import com.tracepcap.story.dto.LlmTestResult;
import com.tracepcap.story.service.LlmConnectionTester;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/system/llm")
@RequiredArgsConstructor
@Tag(name = "LLM Connection", description = "Test the LLM server Story and Insights use")
public class LlmConnectionController {

  private final LlmConnectionTester tester;

  @PostMapping("/test")
  @Operation(
      summary = "Test the LLM connection",
      description =
          "Checks, in order, that the server can be reached, accepts the key, offers the model and"
              + " replies, and lists its models. Blank fields use the current settings, so an empty"
              + " body tests what's in effect and a filled one tests a change before saving it."
              + " Testing other values than the current ones requires the permission to edit the LLM"
              + " connection.")
  public LlmTestResult test(@RequestBody(required = false) LlmTestRequest request) {
    return tester.test(request);
  }
}
