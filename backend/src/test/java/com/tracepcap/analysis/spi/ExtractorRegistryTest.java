package com.tracepcap.analysis.spi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.tracepcap.analysis.service.ExtractionRunService;
import com.tracepcap.analysis.service.ExtractorRunner;
import com.tracepcap.analysis.service.PcapParserService;
import com.tracepcap.common.stage.Tier;
import com.tracepcap.file.entity.FileEntity;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * <b>The playbook's definition of done, for Extract</b> (#512): an extractor is added by writing one
 * class, and nothing else changes.
 *
 * <p>{@code AnalysisService} used to hold a field per extractor, an {@code if} per enable flag, and
 * a manifest call per branch — so a new extractor meant editing the pipeline's core. These tests
 * pass a probe extractor to the runner without touching a line of {@code main}, and assert on what
 * actually happened: the facts it wrote, and the manifest row it earned.
 */
class ExtractorRegistryTest {

  private static final UUID FILE_ID = UUID.randomUUID();

  private final ExtractionRunService manifest = mock(ExtractionRunService.class);

  private static FileEntity file() {
    return FileEntity.builder().id(FILE_ID).enableNdpi(true).enableSuricata(true).build();
  }

  /**
   * An extractor that exists to prove discovery works. One class: it declares its stage by
   * implementing {@link Extractor}, its tier by returning one, and when it applies by answering for
   * itself. Nothing registers it.
   */
  static class ProbeExtractor implements Extractor {
    static final String PROVENANCE = "probe ran";
    boolean ran;

    @Override
    public String name() {
      return "probe-extractor";
    }

    @Override
    public Tier tier() {
      return Tier.DETERMINISTIC;
    }

    @Override
    public String manifestKey() {
      return "probe";
    }

    @Override
    public boolean enabledFor(ExtractionTarget target) {
      return true;
    }

    @Override
    public Outcome extract(ExtractionTarget target) {
      ran = true;
      // Extract writes: prove the target's working set is genuinely mutable.
      target.conversations().forEach(c -> c.setAppName("PROBE"));
      return Outcome.completed(PROVENANCE);
    }
  }

  private static PcapParserService.ConversationInfo conversation() {
    PcapParserService.ConversationInfo c = new PcapParserService.ConversationInfo();
    c.setSrcIp("10.0.0.1");
    c.setDstIp("10.0.0.2");
    return c;
  }

  /** The one that matters: a class nobody registered runs, and its facts land on the capture. */
  @Test
  void anExtractorDeclaredNowhereButItsOwnFileRunsAndItsFactsLand() {
    ProbeExtractor probe = new ProbeExtractor();
    ExtractorRunner runner = new ExtractorRunner(List.of(probe), manifest);
    List<PcapParserService.ConversationInfo> conversations = new ArrayList<>(List.of(conversation()));

    runner.runAll(file(), new File("/tmp/does-not-need-to-exist.pcap"), conversations);

    assertThat(probe.ran).isTrue();
    // The write reached the working set — this is what separates Extract from Scan.
    assertThat(conversations.get(0).getAppName()).isEqualTo("PROBE");
  }

  /** Provenance is the runner's job, not the extractor's — an extractor cannot forget (#501). */
  @Test
  void theManifestRowIsRecordedWithoutTheExtractorAskingForIt() {
    ExtractorRunner runner = new ExtractorRunner(List.of(new ProbeExtractor()), manifest);

    runner.runAll(file(), new File("/tmp/x.pcap"), new ArrayList<>());

    verify(manifest)
        .record(eq(FILE_ID), eq("probe"), eq(ExtractionManifest.Status.COMPLETED), eq(ProbeExtractor.PROVENANCE));
  }

  /** "Not enabled" is an answer, and it must be recorded — absence of a row is not the same claim. */
  @Test
  void aDisabledExtractorIsRecordedAsSkippedRatherThanLeavingNoRow() {
    Extractor disabled =
        new ProbeExtractor() {
          @Override
          public boolean enabledFor(ExtractionTarget target) {
            return false;
          }
        };
    ExtractorRunner runner = new ExtractorRunner(List.of(disabled), manifest);

    runner.runAll(file(), new File("/tmp/x.pcap"), new ArrayList<>());

    verify(manifest)
        .record(eq(FILE_ID), eq("probe"), eq(ExtractionManifest.Status.SKIPPED), any());
  }

  /** One extractor throwing must not cost the others their facts, and must still be recorded. */
  @Test
  void aThrowingExtractorIsIsolatedAndRecordedAsFailed() {
    Extractor boom =
        new ProbeExtractor() {
          @Override
          public String manifestKey() {
            return "boom";
          }

          @Override
          public Outcome extract(ExtractionTarget target) {
            throw new IllegalStateException("ndpiReader died");
          }
        };
    ProbeExtractor survivor = new ProbeExtractor();
    ExtractorRunner runner = new ExtractorRunner(List.of(boom, survivor), manifest);
    List<PcapParserService.ConversationInfo> conversations = new ArrayList<>(List.of(conversation()));

    runner.runAll(file(), new File("/tmp/x.pcap"), conversations);

    assertThat(survivor.ran).as("a peer's failure must not stop this one").isTrue();
    assertThat(conversations.get(0).getAppName()).isEqualTo("PROBE");
    verify(manifest).record(eq(FILE_ID), eq("boom"), eq(ExtractionManifest.Status.FAILED), any());
  }

  /** Order is declared by the module; the runner sorts rather than knowing who goes first. */
  @Test
  void extractorsRunInDeclaredOrder() {
    List<String> sequence = new ArrayList<>();
    ExtractorRunner runner =
        new ExtractorRunner(List.of(ordered("late", 90, sequence), ordered("early", 10, sequence)), manifest);

    runner.runAll(file(), new File("/tmp/x.pcap"), new ArrayList<>());

    assertThat(sequence).containsExactly("early", "late");
  }

  private static Extractor ordered(String name, int order, List<String> sequence) {
    return new Extractor() {
      @Override
      public String name() {
        return name;
      }

      @Override
      public Tier tier() {
        return Tier.DETERMINISTIC;
      }

      @Override
      public int order() {
        return order;
      }

      @Override
      public boolean enabledFor(ExtractionTarget target) {
        return true;
      }

      @Override
      public Outcome extract(ExtractionTarget target) {
        sequence.add(name);
        return Outcome.completed("ok");
      }
    };
  }
}
