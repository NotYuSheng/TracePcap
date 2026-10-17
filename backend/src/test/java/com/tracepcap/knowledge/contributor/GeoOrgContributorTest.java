package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.Findings;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.analysis.spi.ConversationLookup.TlsFacts;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.analysis.spi.GeoOrgLookup.IpAttribution;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class GeoOrgContributorTest {

  private static final UUID FILE = UUID.randomUUID();

  @Mock private ConversationLookup conversationLookup;
  @Mock private GeoOrgLookup geoOrgLookup;

  private ConversationFacts conv(String src, String dst, List<String> suricata) {
    return new ConversationFacts(
        UUID.randomUUID(), FILE,
        new FlowIdentity(src, 49754, dst, 12132, src, 49754, "TCP", 411, 39064, null, null),
        new TlsFacts(null, null, null, null, null, null, null),
        new Findings(null, null, null, List.of(), suricata, List.of(), List.of()));
  }

  @Test
  void enrichesTheAlertedExternalWithCountryAsnOrg() {
    when(conversationLookup.conversationFacts(FILE))
        .thenReturn(List.of(conv("172.16.1.66", "141.98.10.79", List.of("ET MALWARE STRRAT CnC"))));
    when(geoOrgLookup.attributionFor(any()))
        .thenReturn(Map.of("141.98.10.79", new IpAttribution("141.98.10.79", "AS209605", "UAB Host Baltic", "LT")));

    CaseKnowledgeBuilder board = new CaseKnowledgeBuilder(FILE);
    new GeoOrgContributor(conversationLookup, geoOrgLookup).contribute(FILE, board);
    CaseKnowledge k = board.build();

    assertThat(k.entity(EntityRef.external("141.98.10.79"))).isPresent().get()
        .satisfies(e -> assertThat(e.attributes())
            .containsEntry("country", "LT")
            .containsEntry("org", "UAB Host Baltic")
            .containsEntry("asn", "AS209605"));
    // the internal host is not treated as an external endpoint
    assertThat(k.entitiesOfType(EntityType.HOST)).isEmpty();
  }

  @Test
  void enrichesAllExternalsEvenWithoutAnAlert() {
    // Broadened (#813): geo is generally useful, so every external the capture talked to is
    // enriched — not only the alerted ones.
    when(conversationLookup.conversationFacts(FILE))
        .thenReturn(List.of(conv("172.16.1.66", "8.8.8.8", List.of())));
    when(geoOrgLookup.attributionFor(any()))
        .thenReturn(Map.of("8.8.8.8", new IpAttribution("8.8.8.8", "AS15169", "Google LLC", "US")));

    CaseKnowledgeBuilder board = new CaseKnowledgeBuilder(FILE);
    new GeoOrgContributor(conversationLookup, geoOrgLookup).contribute(FILE, board);

    assertThat(board.build().entity(EntityRef.external("8.8.8.8"))).isPresent().get()
        .satisfies(e -> assertThat(e.attributes()).containsEntry("org", "Google LLC"));
  }
}
