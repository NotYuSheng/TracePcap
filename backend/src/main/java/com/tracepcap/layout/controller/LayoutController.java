package com.tracepcap.layout.controller;

import com.tracepcap.layout.dto.LayoutRequest;
import com.tracepcap.layout.dto.LayoutResponse;
import com.tracepcap.layout.service.LayoutService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/layout")
@RequiredArgsConstructor
public class LayoutController {

  private final LayoutService layoutService;

  @PostMapping
  public ResponseEntity<LayoutResponse> computeLayout(@RequestBody LayoutRequest request) {
    log.info(
        "POST /api/layout type={} nodes={} edges={}",
        request.getLayoutType(),
        request.getNodes().size(),
        request.getEdges().size());
    return ResponseEntity.ok(layoutService.computeLayout(request));
  }
}
