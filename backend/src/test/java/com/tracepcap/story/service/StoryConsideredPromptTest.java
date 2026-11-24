package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.knowledge.spi.Considered;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The narrator gets the alternatives the checks ruled out, marked so it can't promote one (#1294). */
class StoryConsideredPromptTest {

  private final StoryService service =
      new StoryService(
          null, null, null, null, null, null, null, new ObjectMapper(), null, null, null, null, null,
          null, null, null, null);

  @Test
  void eachAlternativeComesWithItsReasonAndRule_andAWarningNotToCallItAFinding() {
    StringBuilder prompt = new StringBuilder();
    service.appendConsidered(prompt, List.of(new Considered("c2", "161.0.1.45", "Reputation alone never makes a C2.",
        "on Spamhaus DROP, but 10.0.1.43 never talked to a confirmed C2, so nothing says it is infected.", List.of())));
    assertThat(prompt.toString())
        .contains("## Alternatives considered and ruled out")
        .contains("Never call one a C2, malicious, an attack, or a finding")
        .contains("- [c2] 161.0.1.45: on Spamhaus DROP, but 10.0.1.43 never talked to a confirmed C2")
        .contains("rule: Reputation alone never makes a C2.");
  }

  @Test
  void nothingRuledOut_addsNothing_andALongListIsCounted() {
    StringBuilder empty = new StringBuilder();
    service.appendConsidered(empty, List.of());
    assertThat(empty).isEmpty();

    List<Considered> many = new ArrayList<>();
    for (int i = 0; i < 15; i++) many.add(new Considered("c2", "10.0.0." + i, null, "reason " + i, List.of()));
    StringBuilder prompt = new StringBuilder();
    service.appendConsidered(prompt, many);
    assertThat(prompt.toString()).contains("- … and 3 more ruled out").doesNotContain("10.0.0.14:");
  }
}
