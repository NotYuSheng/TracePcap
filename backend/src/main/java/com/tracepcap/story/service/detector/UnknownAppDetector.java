package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ExtractionManifest;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import com.tracepcap.story.spi.Tier;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UnknownAppDetector implements Scanner {

  private final ConversationLookup conversationLookup;
  private final ExtractionManifest extractionManifest;

  @Override
  public String name() {
    return "unknown-app";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  @Override
  public List<Finding> scan(ScanContext context) {
    UUID fileId = context.fileId();
    long totalConversations = context.totalConversations();
    if (totalConversations == 0) return List.of();

    // app_name IS NULL means "nDPI couldn't identify it" only if nDPI actually ran. When the
    // manifest says it was skipped or failed, every conversation is unidentified for tooling
    // reasons — reporting that as "100% unknown traffic, HIGH" would present an operational gap
    // as a security finding about the user's network (#501). Files analysed before the manifest
    // existed have no row; for those the provenance is unknown and the historic behaviour stands.
    Optional<ExtractionManifest.Run> ndpiRun =
        extractionManifest.runFor(fileId, ExtractionManifest.NDPI);
    if (ndpiRun.isPresent() && ndpiRun.get().status() != ExtractionManifest.Status.COMPLETED) {
      return List.of(coverageGap(ndpiRun.get()));
    }

    long unknown = conversationLookup.unidentifiedAppCount(fileId);
    double pct = (unknown * 100.0) / totalConversations;

    if (pct < 5.0) return List.of();

    Severity severity = pct > 30 ? Severity.HIGH : pct > 10 ? Severity.MEDIUM : Severity.LOW;
    Map<String, Object> metrics = new LinkedHashMap<>();
    metrics.put("unknownCount", unknown);
    metrics.put("totalConversations", totalConversations);
    metrics.put("pct", Math.round(pct * 10.0) / 10.0);

    return List.of(
        Finding.builder()
            .type(FindingType.UNKNOWN_APP)
            .severity(severity)
            .title(String.format("%.1f%% of Traffic Has Unknown Application", pct))
            .summary(
                String.format(
                    "%d of %d conversations (%,.1f%%) could not be identified by nDPI. Unclassified traffic limits visibility and may conceal tunnelling or custom protocols.",
                    unknown, totalConversations, pct))
            .metrics(metrics)
            .affectedIps(List.of())
            .build());
  }

  private static Finding coverageGap(ExtractionManifest.Run run) {
    boolean failed = run.status() == ExtractionManifest.Status.FAILED;
    Map<String, Object> metrics = new LinkedHashMap<>();
    metrics.put("extractor", run.extractor());
    metrics.put("status", run.status().name());
    return Finding.builder()
        .type(FindingType.COVERAGE_GAP)
        .severity(failed ? Severity.MEDIUM : Severity.LOW)
        .title(failed ? "Application Identification Failed" : "Application Identification Skipped")
        .summary(
            String.format(
                "nDPI %s for this capture (%s), so application names are unavailable. This is a tooling gap, not a property of the traffic — unknown-application analysis was not performed.",
                failed ? "failed" : "did not run",
                run.detail() == null ? "no detail" : run.detail()))
        .metrics(metrics)
        .affectedIps(List.of())
        .build();
  }
}
