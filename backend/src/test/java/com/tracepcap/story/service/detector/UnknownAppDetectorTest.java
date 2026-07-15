package com.tracepcap.story.service.detector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.spi.ExtractionManifest;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The #501 regression: {@code app_name IS NULL} must only be reported as unknown *traffic* when
 * nDPI actually ran. A skipped or failed run is a tooling gap, not a security finding.
 */
class UnknownAppDetectorTest {

  private final UUID fileId = UUID.randomUUID();
  private final ConversationRepository repo = mock(ConversationRepository.class);

  private UnknownAppDetector detector(ExtractionManifest manifest) {
    return new UnknownAppDetector(repo, manifest);
  }

  private static ExtractionManifest manifestWith(ExtractionManifest.Run run) {
    return (fileId, extractor) -> Optional.ofNullable(run);
  }

  @Test
  void ndpiSkipped_reportsCoverageGap_notUnknownTraffic() {
    // The literal #501 case: ndpiReader missing → every conversation unidentified. Before the
    // manifest this reported "100% of Traffic Has Unknown Application, HIGH".
    when(repo.countUnknownAppByFileId(any())).thenReturn(100L);
    ExtractionManifest manifest =
        manifestWith(
            new ExtractionManifest.Run(
                ExtractionManifest.NDPI,
                "1",
                ExtractionManifest.Status.SKIPPED,
                "ndpiReader not installed (install libndpi-bin)"));

    List<Finding> findings = detector(manifest).detect(fileId, 100);

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).getType()).isEqualTo(FindingType.COVERAGE_GAP);
    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.LOW);
    assertThat(findings.get(0).getSummary()).contains("tooling gap");
  }

  @Test
  void ndpiFailed_reportsCoverageGap_atMediumSeverity() {
    ExtractionManifest manifest =
        manifestWith(
            new ExtractionManifest.Run(
                ExtractionManifest.NDPI,
                "1",
                ExtractionManifest.Status.FAILED,
                "ndpiReader exited with code 137"));

    List<Finding> findings = detector(manifest).detect(fileId, 100);

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).getType()).isEqualTo(FindingType.COVERAGE_GAP);
    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.MEDIUM);
  }

  @Test
  void ndpiCompleted_highUnknownShare_isARealFinding() {
    when(repo.countUnknownAppByFileId(any())).thenReturn(40L);
    ExtractionManifest manifest =
        manifestWith(
            new ExtractionManifest.Run(
                ExtractionManifest.NDPI, "1", ExtractionManifest.Status.COMPLETED, "12 flows"));

    List<Finding> findings = detector(manifest).detect(fileId, 100);

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).getType()).isEqualTo(FindingType.UNKNOWN_APP);
    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.HIGH);
  }

  @Test
  void legacyFile_noManifestRow_keepsHistoricBehaviour() {
    // Files analysed before the manifest existed have no row: provenance unknown, so the
    // pre-manifest behaviour stands rather than silently suppressing findings.
    when(repo.countUnknownAppByFileId(any())).thenReturn(40L);
    ExtractionManifest manifest = manifestWith(null);

    List<Finding> findings = detector(manifest).detect(fileId, 100);

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).getType()).isEqualTo(FindingType.UNKNOWN_APP);
  }

  @Test
  void ndpiCompleted_lowUnknownShare_noFinding() {
    when(repo.countUnknownAppByFileId(any())).thenReturn(2L);
    ExtractionManifest manifest =
        manifestWith(
            new ExtractionManifest.Run(
                ExtractionManifest.NDPI, "1", ExtractionManifest.Status.COMPLETED, "98 flows"));

    assertThat(detector(manifest).detect(fileId, 100)).isEmpty();
  }
}
