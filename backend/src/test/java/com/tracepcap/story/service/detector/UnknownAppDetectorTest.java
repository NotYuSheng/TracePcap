package com.tracepcap.story.service.detector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ExtractionManifest;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
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
  private final ConversationLookup repo = mock(ConversationLookup.class);

  /**
   * A ScanContext carrying just what this scanner reads. Hand-rolled rather than mocked: the
   * scanner's contract is "everything you need is on the context", and a literal implementation
   * says that more plainly than a stub would.
   */
  private ScanContext context(long totalConversations) {
    return new ScanContext() {
      @Override
      public UUID fileId() {
        return fileId;
      }

      @Override
      public long totalConversations() {
        return totalConversations;
      }

      @Override
      public long totalBytes() {
        return 0;
      }

      @Override
      public List<ConversationFacts> conversations() {
        return List.of();
      }

      @Override
      public List<ConversationFacts> tlsConversations() {
        return List.of();
      }
    };
  }

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
    when(repo.unidentifiedAppCount(any())).thenReturn(100L);
    ExtractionManifest manifest =
        manifestWith(
            new ExtractionManifest.Run(
                ExtractionManifest.NDPI,
                "1",
                ExtractionManifest.Status.SKIPPED,
                "ndpiReader not installed (install libndpi-bin)"));

    List<Finding> findings = detector(manifest).scan(context(100));

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

    List<Finding> findings = detector(manifest).scan(context(100));

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).getType()).isEqualTo(FindingType.COVERAGE_GAP);
    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.MEDIUM);
  }

  @Test
  void ndpiCompleted_highUnknownShare_isARealFinding() {
    when(repo.unidentifiedAppCount(any())).thenReturn(40L);
    ExtractionManifest manifest =
        manifestWith(
            new ExtractionManifest.Run(
                ExtractionManifest.NDPI, "1", ExtractionManifest.Status.COMPLETED, "12 flows"));

    List<Finding> findings = detector(manifest).scan(context(100));

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).getType()).isEqualTo(FindingType.UNKNOWN_APP);
    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.HIGH);
  }

  @Test
  void legacyFile_noManifestRow_keepsHistoricBehaviour() {
    // Files analysed before the manifest existed have no row: provenance unknown, so the
    // pre-manifest behaviour stands rather than silently suppressing findings.
    when(repo.unidentifiedAppCount(any())).thenReturn(40L);
    ExtractionManifest manifest = manifestWith(null);

    List<Finding> findings = detector(manifest).scan(context(100));

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).getType()).isEqualTo(FindingType.UNKNOWN_APP);
  }

  @Test
  void ndpiCompleted_lowUnknownShare_noFinding() {
    when(repo.unidentifiedAppCount(any())).thenReturn(2L);
    ExtractionManifest manifest =
        manifestWith(
            new ExtractionManifest.Run(
                ExtractionManifest.NDPI, "1", ExtractionManifest.Status.COMPLETED, "98 flows"));

    assertThat(detector(manifest).scan(context(100))).isEmpty();
  }
}
