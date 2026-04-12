package com.tracepcap.story.service;

import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.service.detector.*;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/** Orchestrates all deterministic detectors and returns a merged, severity-sorted finding list. */
@Slf4j
@Service
@RequiredArgsConstructor
public class FindingsService {

  private final NdpiRiskDetector ndpiRiskDetector;
  private final BeaconDetector beaconDetector;
  private final TlsAnomalyDetector tlsAnomalyDetector;
  private final VolumeDetector volumeDetector;
  private final FanOutDetector fanOutDetector;
  private final LongSessionDetector longSessionDetector;
  private final UnknownAppDetector unknownAppDetector;
  private final PortProtocolMismatchDetector portProtocolMismatchDetector;
  private final ConversationRepository conversationRepository;

  public List<Finding> detectAll(UUID fileId, long totalConversations, long totalBytes) {
    // Load full conversation list once — shared across detectors that need it
    List<ConversationEntity> all = conversationRepository.findByFileId(fileId);
    List<ConversationEntity> tlsConversations =
        all.stream().filter(c -> c.getTlsIssuer() != null).collect(Collectors.toList());

    List<Finding> findings = new ArrayList<>();

    runDetector("NdpiRisk", () -> findings.addAll(ndpiRiskDetector.detect(fileId)));
    runDetector("Beacon", () -> findings.addAll(beaconDetector.detect(fileId)));
    runDetector("TlsAnomaly", () -> findings.addAll(tlsAnomalyDetector.detect(tlsConversations)));
    runDetector("Volume", () -> findings.addAll(volumeDetector.detect(fileId, totalBytes)));
    runDetector("FanOut", () -> findings.addAll(fanOutDetector.detect(fileId)));
    runDetector("LongSession", () -> findings.addAll(longSessionDetector.detect(fileId)));
    runDetector(
        "UnknownApp", () -> findings.addAll(unknownAppDetector.detect(fileId, totalConversations)));
    runDetector(
        "PortProtocolMismatch", () -> findings.addAll(portProtocolMismatchDetector.detect(all)));

    // Sort by severity (CRITICAL first), then by type for stable ordering
    findings.sort(
        Comparator.comparingInt((Finding f) -> f.getSeverity().ordinal())
            .thenComparing(f -> f.getType().name()));

    log.info(
        "Findings for file {}: {} total ({} CRITICAL, {} HIGH, {} MEDIUM, {} LOW)",
        fileId,
        findings.size(),
        count(findings, Severity.CRITICAL),
        count(findings, Severity.HIGH),
        count(findings, Severity.MEDIUM),
        count(findings, Severity.LOW));
    return findings;
  }

  private void runDetector(String name, Runnable detector) {
    try {
      detector.run();
    } catch (Exception e) {
      log.warn("Detector {} failed: {}", name, e.getMessage());
    }
  }

  private long count(List<Finding> findings, Severity severity) {
    return findings.stream().filter(f -> f.getSeverity() == severity).count();
  }
}
