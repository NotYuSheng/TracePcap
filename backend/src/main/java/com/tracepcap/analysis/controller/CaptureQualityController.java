package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.CaptureQualityResponse;
import com.tracepcap.analysis.service.CaptureQualityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(name = "Capture quality", description = "How complete a capture is, and how fully it was inspected")
public class CaptureQualityController {

  private final CaptureQualityService service;

  @GetMapping("/{fileId}/capture-quality")
  @Operation(
      summary = "How complete a capture is",
      description =
          "Connections already open when the capture began, gaps in TCP streams, undecodable"
              + " packets, and sessions Suricata stopped inspecting, as plain-language notes. Suricata's"
              + " counters are null for captures it didn't run on (or analysed before they were kept).")
  public CaptureQualityResponse get(@PathVariable UUID fileId) {
    return service.forFile(fileId);
  }
}
