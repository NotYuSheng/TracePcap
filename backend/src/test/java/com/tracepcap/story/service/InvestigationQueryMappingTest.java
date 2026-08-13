package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.story.dto.InvestigationQuery;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The investigation agent used to build its own JPA Specification over {@code ConversationEntity}
 * from the story module — a seam bypass (#512 slice 6) and a second definition of "filter
 * conversations", free to drift from the one the conversations table uses.
 *
 * <p>It now maps onto the shared filter descriptor instead. These cover the mapping, which is where
 * the model-facing semantics live; the predicates themselves are the conversations-table path.
 */
class InvestigationQueryMappingTest {

  private final InvestigationService service = new InvestigationService(null);

  private static InvestigationQuery.InvestigationQueryBuilder query() {
    return InvestigationQuery.builder().id("q1").label("test");
  }

  @ParameterizedTest
  @ValueSource(strings = {"UNKNOWN_APP", "unknown", "Unknown", "null", "  "})
  void theModelsSentinelsForAnUnidentifiedAppBecomeAnIsNullFilter(String sentinel) {
    // The model has no way to express SQL NULL, so it writes a word. Passing that word through as
    // an app name would match nothing, and "no results" reads to the agent as "nothing to see".
    ConversationFilterParams filter = service.toFilter(query().appName(sentinel).build());

    assertThat(filter.getAppIsNull()).isTrue();
    assertThat(filter.getApps()).isEmpty();
  }

  @Test
  void arealAppNameFiltersOnTheAppRatherThanOnNull() {
    ConversationFilterParams filter = service.toFilter(query().appName("Telegram").build());

    assertThat(filter.getApps()).containsExactly("Telegram");
    assertThat(filter.getAppIsNull()).isNull();
  }

  @Test
  void protocolIsUppercasedToMatchHowItIsStored() {
    // Conversations store the protocol uppercase ("ARP", "802.11"). The old Specification compared
    // case-insensitively; the shared filter uses an IN, so the casing has to be applied here.
    ConversationFilterParams filter = service.toFilter(query().protocol("tcp").build());

    assertThat(filter.getProtocols()).containsExactly("TCP");
  }

  @Test
  void byteBoundsSurviveOnTheirOwn() {
    ConversationFilterParams filter =
        service.toFilter(query().minBytes(1_000L).maxBytes(9_000L).build());

    assertThat(filter.getMinBytes()).isEqualTo(1_000L);
    assertThat(filter.getMaxBytes()).isEqualTo(9_000L);
  }

  @Test
  void byteBoundsAreDroppedAlongsideSrcIp() {
    // The model tends to pass a host's aggregate total here, which as a per-conversation bound
    // matches nothing. Pinned because it looks like a bug until you know why.
    ConversationFilterParams filter =
        service.toFilter(query().srcIp("10.0.0.1").minBytes(5_000_000L).build());

    assertThat(filter.getSrcIp()).isEqualTo("10.0.0.1");
    assertThat(filter.getMinBytes()).isNull();
  }

  @Test
  void byteBoundsAreDroppedAlongsideRiskType() {
    ConversationFilterParams filter =
        service.toFilter(query().riskType("TLS_CERT_EXPIRED").maxBytes(5_000_000L).build());

    assertThat(filter.getRiskTypes()).containsExactly("TLS_CERT_EXPIRED");
    assertThat(filter.getMaxBytes()).isNull();
  }

  @Test
  void directionalAndFanOutDimensionsPassThrough() {
    ConversationFilterParams filter =
        service.toFilter(
            query().srcIp("10.0.0.1").dstIp("8.8.8.8").dstPort(443).minFlows(20).build());

    assertThat(filter.getSrcIp()).isEqualTo("10.0.0.1");
    assertThat(filter.getDstIp()).isEqualTo("8.8.8.8");
    assertThat(filter.getDstPort()).isEqualTo(443);
    assertThat(filter.getMinFlows()).isEqualTo(20);
  }

  @Test
  void anEmptyQueryFiltersOnNothingButTheFile() {
    ConversationFilterParams filter = service.toFilter(query().build());

    // Every dimension must be null/empty rather than a default that quietly narrows the search.
    assertThat(filter.getSrcIp()).isNull();
    assertThat(filter.getDstIp()).isNull();
    assertThat(filter.getDstPort()).isNull();
    assertThat(filter.getMinBytes()).isNull();
    assertThat(filter.getMaxBytes()).isNull();
    assertThat(filter.getMinFlows()).isNull();
    assertThat(filter.getAppIsNull()).isNull();
    assertThat(filter.getHasRisks()).isNull();
    assertThat(filter.getHasTlsAnomaly()).isNull();
    assertThat(filter.getProtocols()).isEqualTo(List.of());
    assertThat(filter.getApps()).isEqualTo(List.of());
    assertThat(filter.getCategories()).isEqualTo(List.of());
    assertThat(filter.getRiskTypes()).isEqualTo(List.of());
  }

  @Test
  void falseFlagsAreNotSentAsFilters() {
    // hasRisks=false means "the model did not ask for risks", not "only risk-free conversations".
    ConversationFilterParams filter =
        service.toFilter(query().hasRisks(false).hasTlsAnomaly(false).build());

    assertThat(filter.getHasRisks()).isNull();
    assertThat(filter.getHasTlsAnomaly()).isNull();
  }

  @Test
  void resultsAreOrderedByVolumeSoTheAgentSeesTheLargestFlowsFirst() {
    ConversationFilterParams filter = service.toFilter(query().build());

    assertThat(filter.getSortBy()).isEqualTo("totalBytes");
    assertThat(filter.getSortDir()).isEqualTo("desc");
  }
}
