package com.tracepcap.insights.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Characterisation tests for {@code SnapshotInsightService}'s LLM-response salvaging (#659, phase
 * 4). Fifth and final service slice, after {@code subnets.service} (#688), {@code report} (#690),
 * {@code intelligence.service} (#692) and {@code monitor.service} (#695).
 *
 * <p>{@code extractJson} exists because models do not reliably return bare JSON — they wrap it in
 * fences, add prose, and emit comments that JSON does not allow. It is therefore a pile of regex
 * heuristics operating on untrusted text, and every one of them is a silent-failure risk: a bad
 * salvage does not throw, it produces JSON that parses into the wrong insight.
 *
 * <p>Pins current behaviour, including where the heuristics are lossy. Nothing is corrected.
 */
class SnapshotInsightJsonCharacterisationTest {

  private static final SnapshotInsightService SERVICE = newServiceWithoutCollaborators();

  private static SnapshotInsightService newServiceWithoutCollaborators() {
    try {
      Constructor<?> ctor = SnapshotInsightService.class.getDeclaredConstructors()[0];
      ctor.setAccessible(true);
      return (SnapshotInsightService) ctor.newInstance(new Object[ctor.getParameterCount()]);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          "SnapshotInsightService's constructor changed — update this test", e);
    }
  }

  private static String extractJson(String content) {
    try {
      Method m = SnapshotInsightService.class.getDeclaredMethod("extractJson", String.class);
      m.setAccessible(true);
      return (String) m.invoke(SERVICE, content);
    } catch (InvocationTargetException e) {
      throw (RuntimeException) e.getCause();
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("extractJson changed — update this test", e);
    }
  }

  // --- rejection -------------------------------------------------------------

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {"", "   ", "\n\t"})
  void extractJson_throwsOnAnEmptyResponse(String content) {
    // A RuntimeException rather than a checked one or a null return, so the caller records the
    // insight as failed rather than storing an empty body.
    assertThatThrownBy(() -> extractJson(content))
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("Empty LLM response");
  }

  // --- fence stripping -------------------------------------------------------

  @Test
  void extractJson_stripsFencedCodeBlocks() {
    assertThat(extractJson("```json\n{\"a\":1}\n```")).isEqualTo("{\"a\":1}");
  }

  @Test
  void extractJson_stripsBareFencesToo() {
    assertThat(extractJson("```\n{\"a\":1}\n```")).isEqualTo("{\"a\":1}");
  }

  // --- brace slicing ---------------------------------------------------------

  @Test
  void extractJson_discardsProseAroundTheObject() {
    // Models routinely prepend "Here is the JSON:" and append a summary.
    assertThat(extractJson("Sure! Here you go:\n{\"a\":1}\nHope that helps."))
        .isEqualTo("{\"a\":1}");
  }

  @Test
  void extractJson_slicesToTheLastBraceSoNestedObjectsSurvive() {
    String json = "{\"a\":{\"b\":2}}";
    assertThat(extractJson("noise " + json + " noise")).isEqualTo(json);
  }

  @Test
  void extractJson_returnsContentUnchangedWhenThereIsNoObject() {
    // No braces: nothing to salvage, so the raw text is handed on and fails at the parse step
    // with the model's actual words, which is more debuggable than an empty string.
    assertThat(extractJson("I cannot help with that.")).isEqualTo("I cannot help with that.");
  }

  @Test
  void extractJson_returnsContentUnchangedWhenBracesAreInverted() {
    // "}" before "{" fails the `end > start` guard.
    assertThat(extractJson("} not json {")).isEqualTo("} not json {");
  }

  // --- comment stripping -----------------------------------------------------

  @Test
  void extractJson_removesWholeLineComments() {
    assertThat(extractJson("{\n  // explanation\n  \"a\":1\n}"))
        .isEqualTo("{\n  \n  \"a\":1\n}");
  }

  @Test
  void extractJson_removesTrailingCommentsAfterACommaButKeepsTheComma() {
    assertThat(extractJson("{\"a\":1, // note\n\"b\":2}")).isEqualTo("{\"a\":1,\n\"b\":2}");
  }

  @Test
  void extractJson_preservesUrlsThatContainDoubleSlashes() {
    // The comment patterns are anchored at line start or immediately after a comma, so a "//"
    // inside a string value survives. Worth pinning: a naive "strip everything after //" would
    // corrupt every URL the model reports, silently and unrecoverably.
    String json = "{\"url\":\"https://example.com/a\"}";
    assertThat(extractJson(json)).isEqualTo(json);
  }

  @Test
  void extractJson_stripsAnIndentedCommentLineButLeavesItsIndentation() {
    // The replacement keeps group 1, so the line becomes blank-but-indented rather than being
    // removed. Harmless for a JSON parser; pinned because "tidying" it changes the output.
    assertThat(extractJson("{\n    // c\n\"a\":1}")).isEqualTo("{\n    \n\"a\":1}");
  }

  // --- formatValue -----------------------------------------------------------

  @Test
  void formatValue_joinsEntriesAndRendersNullAsAnEmDash() throws Exception {
    Method m = SnapshotInsightService.class.getDeclaredMethod("formatValue", Map.class);
    m.setAccessible(true);
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("hosts", 3);
    value.put("subnet", "10.0.0.0/8");

    assertThat(m.invoke(SERVICE, value)).isEqualTo("hosts=3, subnet=10.0.0.0/8");
    assertThat(m.invoke(SERVICE, (Map<String, Object>) null)).isEqualTo("—");
  }
}
