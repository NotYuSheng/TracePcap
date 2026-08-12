package com.tracepcap.story.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.story.dto.Hypothesis;
import com.tracepcap.story.dto.InvestigationQuery;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * The investigation query, declared as a native tool so an OpenAI-compatible server constrains
 * generation to its real schema (#623).
 *
 * <p>Before this, the model was handed a JSON example in the prompt and asked to imitate it; every
 * field name and type was a guess it had to get right unaided. Here the 12 filter fields are typed
 * on the wire, and the descriptions carry the semantics a type cannot — which of these are
 * per-conversation and which are not, which are exact matches, which vocabulary is legal.
 *
 * <p>One tool call is one hypothesis paired with the query that tests it. The model emits several
 * in a turn; ids are assigned here, in emission order, so the {@code queryRef} link the UI renders
 * cannot be dangling — under the free-text path the model wrote those ids itself and could mismatch
 * them.
 */
@Slf4j
@Component
public class InvestigationTools {

  public static final String QUERY_CONVERSATIONS = "query_conversations";

  private final ObjectMapper objectMapper;

  /**
   * Tolerant of unknown properties by construction, not by luck: the arguments carry {@code
   * hypothesis} and {@code confidence}, which belong to the hypothesis rather than the query, and a
   * model that invents a field must not cost us the whole call.
   */
  private final com.fasterxml.jackson.databind.ObjectReader queryReader;

  public InvestigationTools(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
    this.queryReader =
        objectMapper
            .readerFor(InvestigationQuery.class)
            .without(
                com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
  }

  /** The hypotheses and queries recovered from one investigation-planning turn. */
  public record InvestigationPlan(List<InvestigationQuery> queries, List<Hypothesis> hypotheses) {
    public boolean isEmpty() {
      return queries.isEmpty();
    }
  }

  /**
   * Declaration of {@link #QUERY_CONVERSATIONS}.
   *
   * <p>Every description here is load-bearing. The two that matter most — the per-conversation
   * meaning of the byte bounds, and leaving {@code appName} absent rather than naming a sentinel —
   * are the model behaviours {@link InvestigationQuerySanitizer} exists to clean up after; stating
   * them in the schema is what lets the constrained path skip that cleanup.
   */
  public LlmToolSpec queryConversationsTool() {
    return new LlmToolSpec(
        QUERY_CONVERSATIONS,
        "Search the capture's conversations for evidence that tests one hypothesis. "
            + "Call once per hypothesis, up to 5 times. Every call must set at least one filter "
            + "field besides label/hypothesis/confidence — a call with no filters matches the "
            + "whole capture and is discarded. Only use IP addresses, ports, protocols and risk "
            + "types that appear in the findings or aggregates you were given; do not invent values.",
        LlmToolSpec.schema()
            .property("label", "string", "Short description of what this query is looking for.")
            .property(
                "hypothesis",
                "string",
                "One-sentence testable hypothesis this query gathers evidence for, naming specific"
                    + " IPs or ports.")
            .enumProperty(
                "confidence",
                "Your confidence in the hypothesis before seeing the results.",
                List.of("HIGH", "MEDIUM", "LOW"))
            .property("srcIp", "string", "Exact source IP address.")
            .property("dstIp", "string", "Exact destination IP address.")
            .property("dstPort", "integer", "Exact destination port number.")
            .property("protocol", "string", "Transport protocol, e.g. TCP, UDP, ICMP.")
            .property(
                "appName",
                "string",
                "Exact application name as identified by nDPI, e.g. TLS, DNS, HTTP. To search for"
                    + " traffic nDPI could NOT identify, omit this field entirely — do not pass"
                    + " \"unknown\", \"UNKNOWN_APP\", \"null\" or an empty string.")
            .property("category", "string", "Exact traffic category label.")
            .property(
                "hasRisks", "boolean", "True to return only conversations carrying a flow risk.")
            .property(
                "hasTlsAnomaly",
                "boolean",
                "True to return only conversations with TLS certificate anomalies.")
            .property(
                "riskType",
                "string",
                "Exact flow-risk identifier as it appears in the findings, e.g."
                    + " suspicious_entropy, unidirectional_traffic.")
            .property(
                "minBytes",
                "integer",
                "Minimum bytes in a SINGLE conversation. This is a per-conversation bound, never an"
                    + " aggregate: passing a host's total byte count here matches nothing, because"
                    + " no individual flow is that large. Omit unless you specifically want large"
                    + " individual flows.")
            .property(
                "maxBytes",
                "integer",
                "Maximum bytes in a SINGLE conversation. Per-conversation, never an aggregate.")
            .property(
                "minFlows",
                "integer",
                "Minimum number of conversations the source IP must have in this capture. Use this"
                    + " for fan-out and scanning behaviour.")
            .require("label", "hypothesis", "confidence")
            .build());
  }

  /**
   * Turn one turn's tool calls into queries and their hypotheses.
   *
   * <p>A call whose arguments will not parse is skipped rather than failing the plan: partial
   * evidence beats none, which is the same bargain the free-text path already makes.
   */
  public InvestigationPlan parse(LlmToolResponse response) {
    List<InvestigationQuery> queries = new ArrayList<>();
    List<Hypothesis> hypotheses = new ArrayList<>();

    for (LlmToolResponse.ToolCall call : response.callsTo(QUERY_CONVERSATIONS)) {
      String id = "q" + (queries.size() + 1);
      try {
        JsonNode args = objectMapper.readTree(call.argumentsJson());
        InvestigationQuery query = queryReader.readValue(args);
        query.setId(id);
        if (query.getLabel() == null || query.getLabel().isBlank()) {
          query.setLabel("Investigation query " + id);
        }
        queries.add(query);

        String text = args.path("hypothesis").asText(null);
        if (text != null && !text.isBlank()) {
          hypotheses.add(
              Hypothesis.builder()
                  .id("h" + (hypotheses.size() + 1))
                  .queryRef(id)
                  .hypothesis(text)
                  .confidence(confidenceOf(args.path("confidence").asText(null)))
                  .build());
        }
      } catch (Exception e) {
        log.warn("Skipping malformed {} tool call: {}", QUERY_CONVERSATIONS, e.getMessage());
      }
    }

    log.info(
        "Parsed {} tool call(s) into {} queries and {} hypotheses",
        response.toolCalls().size(),
        queries.size(),
        hypotheses.size());
    return new InvestigationPlan(queries, hypotheses);
  }

  private static String confidenceOf(String raw) {
    if (raw == null) return "MEDIUM";
    String upper = raw.trim().toUpperCase();
    return switch (upper) {
      case "HIGH", "MEDIUM", "LOW" -> upper;
      default -> "MEDIUM";
    };
  }
}
