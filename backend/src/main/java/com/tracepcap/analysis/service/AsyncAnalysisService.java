package com.tracepcap.analysis.service;

import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/** Service for async analysis operations */
@Slf4j
@Service
@RequiredArgsConstructor
public class AsyncAnalysisService {

  private final AnalysisService analysisService;

  @Async("asyncAnalysisExecutor")
  public void analyzeFileAsync(UUID fileId) {
    log.info("Starting async analysis for file: {}", fileId);
    try {
      analysisService.analyzeFile(fileId);
      log.info("Completed async analysis for file: {}", fileId);
    } catch (Exception e) {
      log.error("Failed async analysis for file {}: {}", fileId, e.getMessage(), e);
    }
  }
}
