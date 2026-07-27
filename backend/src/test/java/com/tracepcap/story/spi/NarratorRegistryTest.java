package com.tracepcap.story.spi;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.AnalysisSummaryLookup.CaptureSummary;
import com.tracepcap.common.stage.Tier;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.NarrativeSection;
import com.tracepcap.story.dto.StoryAggregates;
import com.tracepcap.story.service.NarratorRunner;
import com.tracepcap.story.service.narrator.CoverageNarrator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * <b>The playbook's definition of done, for Narrate</b> (#512): a narrator is added by writing one
 * class, and nothing else changes.
 *
 * <p>The story used to be a single LLM call behind a single prompt, so contributing a section meant
 * editing that prompt — and every section had to come from a language model, because there was only
 * one way in. These tests pass a probe narrator to the runner without touching a line of {@code
 * main}, and assert on the sections that come back.
 */
class NarratorRegistryTest {

  private static final UUID FILE_ID = UUID.randomUUID();

  /** A narrator that exists to prove discovery works. One class; nothing registers it. */
  static class ProbeNarrator implements Narrator {
    static final String TITLE = "probe-narrator ran";

    @Override
    public String name() {
      return "probe-narrator";
    }

    @Override
    public Tier tier() {
      return Tier.DETERMINISTIC;
    }

    @Override
    public List<NarrativeSection> narrate(NarrationContext context) {
      return List.of(
          NarrativeSection.builder()
              .title(TITLE)
              .type(NarrativeSection.SectionType.summary)
              .content("Emitted by the registry test's probe narrator.")
              .build());
    }
  }

  private static NarrationContext context(StoryAggregates aggregates, CaptureSummary summary) {
    return new NarrationContext() {
      @Override
      public UUID fileId() {
        return FILE_ID;
      }

      @Override
      public CaptureSummary summary() {
        return summary;
      }

      @Override
      public List<Finding> findings() {
        return List.of();
      }

      @Override
      public StoryAggregates aggregates() {
        return aggregates;
      }

      @Override
      public String analystContext() {
        return null;
      }
    };
  }

  private static CaptureSummary summary() {
    return new CaptureSummary(10L, 100L, java.time.LocalDateTime.now(), java.time.LocalDateTime.now(), 5L, Map.of());
  }

  /** The one that matters: a class nobody registered contributes to the story. */
  @Test
  void aNarratorDeclaredNowhereButItsOwnFileContributesItsSection() {
    NarratorRunner runner = new NarratorRunner(List.of(new ProbeNarrator()));

    List<NarrativeSection> sections =
        runner.narrateAll(context(StoryAggregates.builder().build(), summary()));

    assertThat(sections).extracting(NarrativeSection::getTitle).contains(ProbeNarrator.TITLE);
  }

  /**
   * The registry's point, beyond registration: a section can now be deterministic. Before it, every
   * section came from the one LLM call — so "state what the capture could not tell us", which is
   * exactly the section a model should not write, had no way to exist.
   */
  @Test
  void aDeterministicNarratorStatesTheGapsAnLlmWouldHaveInvented() {
    // unknownAppPct == null means nDPI did not complete — the share is unknowable (#501).
    StoryAggregates gapped = StoryAggregates.builder().unknownAppPct(null).build();
    NarratorRunner runner = new NarratorRunner(List.of(new CoverageNarrator()));

    List<NarrativeSection> sections = runner.narrateAll(context(gapped, summary()));

    assertThat(sections).hasSize(1);
    assertThat(sections.get(0).getContent())
        .contains("Application identification did not run")
        .contains("tooling gap, not a property of the network");
  }

  /** Nothing to caveat, nothing to say — a section that exists to fill a slot teaches skimming. */
  @Test
  void theCoverageNarratorContributesNothingWhenThereAreNoGaps() {
    StoryAggregates complete = StoryAggregates.builder().unknownAppPct(12.5).build();
    NarratorRunner runner = new NarratorRunner(List.of(new CoverageNarrator()));

    assertThat(runner.narrateAll(context(complete, summary()))).isEmpty();
  }

  /** Order is declared by the module; the runner sorts rather than knowing who leads. */
  @Test
  void narratorsContributeInDeclaredOrder() {
    NarratorRunner runner =
        new NarratorRunner(List.of(titled("last", 90), titled("first", 10)));

    assertThat(runner.narrateAll(context(StoryAggregates.builder().build(), summary())))
        .extracting(NarrativeSection::getTitle)
        .containsExactly("first", "last");
  }

  /** One narrator throwing costs its own section — a story missing one beats no story. */
  @Test
  void aThrowingNarratorIsIsolated() {
    Narrator boom =
        new ProbeNarrator() {
          @Override
          public String name() {
            return "explodes";
          }

          @Override
          public List<NarrativeSection> narrate(NarrationContext context) {
            throw new IllegalStateException("the model refused");
          }
        };
    NarratorRunner runner = new NarratorRunner(List.of(boom, new ProbeNarrator()));

    assertThat(runner.narrateAll(context(StoryAggregates.builder().build(), summary())))
        .extracting(NarrativeSection::getTitle)
        .containsExactly(ProbeNarrator.TITLE);
  }

  private static Narrator titled(String title, int order) {
    return new Narrator() {
      @Override
      public String name() {
        return title;
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
      public List<NarrativeSection> narrate(NarrationContext context) {
        return List.of(NarrativeSection.builder().title(title).content("x").build());
      }
    };
  }
}
