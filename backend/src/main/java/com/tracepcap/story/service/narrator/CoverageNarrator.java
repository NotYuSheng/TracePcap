package com.tracepcap.story.service.narrator;

import com.tracepcap.common.stage.Tier;
import com.tracepcap.story.dto.NarrativeSection;

import com.tracepcap.story.spi.NarrationContext;
import com.tracepcap.story.spi.Narrator;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * States what this capture could <em>not</em> tell us, before anything is claimed about what it did.
 *
 * <p><b>Deterministic on purpose.</b> This is the section a language model should never write: it is
 * about the limits of the evidence, and a model asked to describe gaps will reach for plausible
 * prose rather than the actual gaps. Assembled from counts instead — no model, nothing to invent.
 *
 * <p>It also demonstrates what the {@link Narrator} seam is for. Before the registry, the story was
 * one LLM call, so every section had to come from a model because there was only one way in. This
 * one is {@link Tier#DETERMINISTIC} and sits alongside the LLM prose; the tier is now a property of
 * the section rather than an assumption about the whole story.
 *
 * <p>Contributes nothing when there is nothing to caveat — an empty section teaches readers to skim.
 */
@Component
public class CoverageNarrator implements Narrator {

  @Override
  public String name() {
    return "coverage";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  /** First: a reader should know the keyhole's shape before reading what was seen through it. */
  @Override
  public int order() {
    return 5;
  }

  @Override
  public List<NarrativeSection> narrate(NarrationContext context) {
    List<String> caveats = new ArrayList<>();

    // Null means nDPI did not complete — the share is unknowable, not zero and not 100% (#501).
    if (context.aggregates() != null && context.aggregates().getUnknownAppPct() == null) {
      caveats.add(
          "Application identification did not run for this capture, so the share of unidentified"
              + " traffic is unknown. Any statement about which applications were present is"
              + " incomplete — this is a tooling gap, not a property of the network.");
    }

    if (context.summary() != null
        && (context.summary().startTime() == null || context.summary().endTime() == null)) {
      caveats.add(
          "The capture carries no usable timestamps, so nothing here can be placed in time or"
              + " described as a sequence.");
    }

    if (caveats.isEmpty()) return List.of();

    return List.of(
        NarrativeSection.builder()
            .title("What This Capture Cannot Tell Us")
            .type(NarrativeSection.SectionType.summary)
            .content(
                "Read everything below with these limits in mind:\n\n- "
                    + String.join("\n- ", caveats))
            .build());
  }
}
