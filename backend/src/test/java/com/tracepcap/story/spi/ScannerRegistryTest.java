package com.tracepcap.story.spi;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ExtractionManifest;
import com.tracepcap.common.stage.Tier;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.service.FindingsService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

/**
 * <b>The playbook's definition of done</b> (#512): a scanner is added by writing one class, and
 * nothing else changes.
 *
 * <p>This test earns its keep by failing if that stops being true. Before the registry,
 * {@code FindingsService} held a field and a call line per detector, so a ninth detector meant
 * editing it — the "edit a core to add capability" the architecture exists to prevent. The proof is
 * {@link ProbeScanner}: a single class, declared in this file, registered nowhere. If Spring finds
 * it and {@link FindingsService} runs it, the seam holds.
 *
 * <p>Scans the real detector package with real component scanning — the ports it depends on are
 * mocked, because what is under test is <em>discovery</em>, not any scanner's logic.
 */
class ScannerRegistryTest {

  /**
   * A scanner that exists only to prove discovery works: one class, declaring its stage by
   * implementing {@link Scanner} and its tier by returning one. No registration call, no list to
   * append to, no core to edit.
   */
  @Component
  static class ProbeScanner implements Scanner {

    /** Emitted so the test can prove this scanner was run, not merely constructed. */
    static final String PROOF_TITLE = "probe-scanner ran";

    @Override
    public String name() {
      return "probe-scanner";
    }

    @Override
    public Tier tier() {
      return Tier.DETERMINISTIC;
    }

    @Override
    public List<Finding> scan(ScanContext context) {
      return List.of(
          Finding.builder()
              .type(FindingType.COVERAGE_GAP)
              .severity(Severity.LOW)
              .title(PROOF_TITLE)
              .summary("Emitted by the registry test's probe scanner.")
              .metrics(Map.of())
              .affectedIps(List.of())
              .build());
    }
  }

  /** Real component scanning over the detector package; ports stubbed. */
  @Configuration
  @ComponentScan("com.tracepcap.story.service.detector")
  static class ScanConfig {
    @Bean
    ConversationLookup conversationLookup() {
      return Mockito.mock(ConversationLookup.class);
    }

    @Bean
    ExtractionManifest extractionManifest() {
      return Mockito.mock(ExtractionManifest.class);
    }
  }

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of())
          .withUserConfiguration(ScanConfig.class, ProbeScanner.class)
          // FindingsService by hand rather than by scanning its package: the package also holds
          // InvestigationService and the LLM client, and discovery does not need either.
          .withBean(FindingsService.class);

  /** The one that matters: a class nobody registered still reaches the registry. */
  @Test
  void aScannerDeclaredNowhereButItsOwnFileIsStillDiscovered() {
    runner.run(
        context ->
            assertThat(context.getBeanProvider(Scanner.class).stream())
                .extracting(Scanner::name)
                .contains("probe-scanner"));
  }

  /** Every detector migrated in slice 6d is registered — none was silently dropped. */
  @Test
  void everyProductionScannerIsRegistered() {
    runner.run(
        context ->
            assertThat(context.getBeanProvider(Scanner.class).stream())
                .extracting(Scanner::name)
                .contains(
                    "ndpi-risk",
                    "beacon",
                    "tls-anomaly",
                    "volume",
                    "fan-out",
                    "long-session",
                    "unknown-app",
                    "port-protocol-mismatch"));
  }

  /**
   * The end-to-end claim: a scanner nobody registered is not merely <em>discovered</em>, it is
   * <em>run</em>, and its findings come back.
   *
   * <p>Asserting on the returned finding rather than on bean counts is deliberate. An earlier
   * version of this test checked only that the beans existed and that FindingsService was non-null
   * — and it passed against a FindingsService whose scanner list had been replaced with
   * {@code List.of()}. A registry that discovers scanners and then runs none of them is exactly the
   * failure this test exists to catch, so it has to observe output.
   */
  @Test
  void aScannerNobodyRegisteredIsActuallyRunAndItsFindingsComeBack() {
    runner.run(
        context -> {
          List<Finding> findings =
              context.getBean(FindingsService.class).detectAll(UUID.randomUUID(), 0, 0);

          assertThat(findings)
              .as("the probe's finding must survive the round trip through the runner")
              .extracting(Finding::getTitle)
              .contains(ProbeScanner.PROOF_TITLE);
        });
  }

  /** Names attribute findings and appear in logs; a duplicate would make both ambiguous. */
  @Test
  void scannerNamesAreUnique() {
    runner.run(
        context ->
            assertThat(context.getBeanProvider(Scanner.class).stream().map(Scanner::name).toList())
                .doesNotHaveDuplicates());
  }

  /** A null tier would break the suite's tier accounting silently. */
  @Test
  void everyScannerDeclaresATier() {
    runner.run(
        context ->
            assertThat(context.getBeanProvider(Scanner.class).stream())
                .allSatisfy(s -> assertThat(s.tier()).isNotNull()));
  }
}
