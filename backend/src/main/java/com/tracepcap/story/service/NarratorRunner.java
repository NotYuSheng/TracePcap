package com.tracepcap.story.service;

import com.tracepcap.common.stage.Tier;
import com.tracepcap.story.dto.NarrativeSection;
import com.tracepcap.story.spi.NarrationContext;
import com.tracepcap.story.spi.Narrator;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Runs every {@link Narrator} on the classpath and returns their sections, in declared order.
 *
 * <p><b>It names no narrator.</b> Adding one is adding one class (#512). Before this, the story was
 * a single LLM call and a single prompt: contributing a section meant editing that prompt, which is
 * the "edit a core to add capability" this architecture exists to prevent — and it meant every
 * section had to come from a language model, because there was only one way in.
 *
 * <p>That is the interesting part. A narrator can now be {@link Tier#DETERMINISTIC} — a section
 * assembled from counts, with no model involved and no chance of invention — sitting alongside the
 * LLM-driven prose. The tier is visible per section rather than assumed for the whole story.
 *
 * <p>Failures are isolated: one narrator throwing costs its own sections, because a story missing a
 * section still beats no story.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class NarratorRunner {

  private final List<Narrator> narrators;

  /** Every narrator's sections, ordered, with failures isolated. */
  public List<NarrativeSection> narrateAll(NarrationContext context) {
    List<Narrator> ordered =
        narrators.stream().sorted(Comparator.comparingInt(Narrator::order)).toList();

    List<NarrativeSection> sections = new ArrayList<>();
    for (Narrator narrator : ordered) {
      try {
        sections.addAll(narrator.narrate(context));
      } catch (Exception e) {
        // The whole exception, not getMessage(): an NPE's message is null.
        log.warn("Narrator {} failed for file {}", narrator.name(), context.fileId(), e);
      }
    }

    log.info(
        "Narrate for file {}: {} section(s) from {} narrator(s) ({})",
        context.fileId(),
        sections.size(),
        ordered.size(),
        tierBreakdown(ordered));
    return sections;
  }

  private static String tierBreakdown(List<Narrator> narrators) {
    return narrators.stream()
        .collect(Collectors.groupingBy(Narrator::tier, Collectors.counting()))
        .entrySet()
        .stream()
        .sorted(Comparator.comparing(e -> e.getKey().name()))
        .map(e -> e.getValue() + " " + e.getKey())
        .collect(Collectors.joining(", "));
  }

  /** Exposed for the narrate-registry test: which narrators Spring discovered. */
  List<String> registeredNarratorNames() {
    return narrators.stream().map(Narrator::name).sorted().toList();
  }
}
