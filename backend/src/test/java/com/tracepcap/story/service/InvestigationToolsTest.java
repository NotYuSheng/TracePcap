package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Binding of {@code query_conversations} tool calls onto the DTOs the rest of Story mode already
 * speaks (#623).
 */
class InvestigationToolsTest {

  private final InvestigationTools tools = new InvestigationTools(new ObjectMapper());

  private static LlmToolResponse constrained(String... argumentJsons) {
    return LlmToolResponse.constrained(
        java.util.Arrays.stream(argumentJsons)
            .map(a -> new LlmToolResponse.ToolCall(InvestigationTools.QUERY_CONVERSATIONS, a))
            .toList(),
        null);
  }

  @Test
  void bindsTypedArgumentsOntoTheQuery() {
    var plan =
        tools.parse(
            constrained(
                """
                {"label":"Beacon to 5.6.7.8","hypothesis":"10.0.0.5 beacons out",
                 "confidence":"HIGH","srcIp":"10.0.0.5","dstPort":4444,"protocol":"TCP",
                 "hasRisks":true,"minFlows":20}
                """));

    assertThat(plan.queries())
        .singleElement()
        .satisfies(
            q -> {
              assertThat(q.getSrcIp()).isEqualTo("10.0.0.5");
              assertThat(q.getDstPort()).isEqualTo(4444);
              assertThat(q.getProtocol()).isEqualTo("TCP");
              assertThat(q.getHasRisks()).isTrue();
              assertThat(q.getMinFlows()).isEqualTo(20);
              assertThat(q.getLabel()).isEqualTo("Beacon to 5.6.7.8");
            });
  }

  @Test
  void pairsEachHypothesisWithItsOwnQuery() {
    var plan =
        tools.parse(
            constrained(
                "{\"label\":\"a\",\"hypothesis\":\"first\",\"confidence\":\"HIGH\",\"srcIp\":\"10.0.0.1\"}",
                "{\"label\":\"b\",\"hypothesis\":\"second\",\"confidence\":\"LOW\",\"dstPort\":53}"));

    assertThat(plan.queries()).extracting("id").containsExactly("q1", "q2");
    // queryRef is assigned here, so it cannot dangle the way a model-authored id could
    assertThat(plan.hypotheses())
        .extracting("id", "queryRef", "hypothesis", "confidence")
        .containsExactly(
            org.assertj.core.groups.Tuple.tuple("h1", "q1", "first", "HIGH"),
            org.assertj.core.groups.Tuple.tuple("h2", "q2", "second", "LOW"));
  }

  @Test
  void keepsGoodCallsWhenOneIsMalformed() {
    var plan =
        tools.parse(
            constrained(
                "{\"label\":\"good\",\"hypothesis\":\"h\",\"confidence\":\"HIGH\",\"srcIp\":\"10.0.0.1\"}",
                "not json at all",
                "{\"label\":\"also good\",\"hypothesis\":\"h2\",\"confidence\":\"MEDIUM\",\"dstPort\":80}"));

    assertThat(plan.queries()).hasSize(2).extracting("label").containsExactly("good", "also good");
  }

  @Test
  void unknownArgumentsDoNotDiscardTheCall() {
    var plan =
        tools.parse(
            constrained(
                "{\"label\":\"l\",\"hypothesis\":\"h\",\"confidence\":\"HIGH\",\"srcIp\":\"10.0.0.1\","
                    + "\"timeWindow\":\"14:00-15:00\"}"));

    assertThat(plan.queries())
        .singleElement()
        .satisfies(q -> assertThat(q.getSrcIp()).isEqualTo("10.0.0.1"));
  }

  @Test
  void unusableConfidenceFallsBackRatherThanFailing() {
    var plan =
        tools.parse(
            constrained(
                "{\"label\":\"l\",\"hypothesis\":\"h\",\"confidence\":\"pretty sure\",\"dstPort\":22}"));

    assertThat(plan.hypotheses())
        .singleElement()
        .satisfies(h -> assertThat(h.getConfidence()).isEqualTo("MEDIUM"));
  }

  @Test
  void ignoresCallsToOtherTools() {
    var response =
        LlmToolResponse.constrained(
            List.of(
                new LlmToolResponse.ToolCall("some_other_tool", "{\"srcIp\":\"10.0.0.9\"}"),
                new LlmToolResponse.ToolCall(
                    InvestigationTools.QUERY_CONVERSATIONS,
                    "{\"label\":\"l\",\"hypothesis\":\"h\",\"confidence\":\"HIGH\",\"dstPort\":443}")),
            null);

    var plan = tools.parse(response);

    assertThat(plan.queries())
        .singleElement()
        .satisfies(q -> assertThat(q.getDstPort()).isEqualTo(443));
  }

  @Test
  @SuppressWarnings("unchecked")
  void declaresEveryFilterFieldTheExecutorCanApply() {
    var spec = tools.queryConversationsTool();
    var properties = (Map<String, Object>) spec.parameters().get("properties");

    assertThat(spec.name()).isEqualTo("query_conversations");
    assertThat(properties)
        .containsKeys(
            "srcIp",
            "dstIp",
            "dstPort",
            "protocol",
            "appName",
            "category",
            "hasRisks",
            "hasTlsAnomaly",
            "riskType",
            "minBytes",
            "maxBytes",
            "minFlows");
    assertThat(spec.parameters().get("required"))
        .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(String.class))
        .containsExactlyInAnyOrder("label", "hypothesis", "confidence");
    // The two workarounds the schema is meant to make unnecessary are stated at the point of
    // generation, not left to the prompt.
    assertThat(((Map<String, Object>) properties.get("minBytes")).get("description").toString())
        .contains("per-conversation");
    assertThat(((Map<String, Object>) properties.get("appName")).get("description").toString())
        .contains("omit this field entirely");
  }
}
