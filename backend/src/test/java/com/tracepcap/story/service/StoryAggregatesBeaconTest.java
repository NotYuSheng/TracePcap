package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.Findings;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.analysis.spi.ConversationLookup.TlsFacts;
import com.tracepcap.analysis.spi.ExtractionManifest;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.common.net.LocalityPolicy;
import com.tracepcap.common.net.LocalityRules;
import com.tracepcap.story.dto.StoryAggregates;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The Traffic-intelligence panel's beacon candidates must agree with the beacon detector (#823): they
 * used to be a second copy of the algorithm, so a domain controller's NetBIOS keepalive was listed
 * here as a beacon candidate — once per protocol view — after the detector had stopped reporting it.
 */
class StoryAggregatesBeaconTest {

  private static final UUID FILE = UUID.randomUUID();
  private static final LocalDateTime T0 = LocalDateTime.of(2024, 7, 30, 10, 41, 10);
  private static final TlsFacts NO_TLS = new TlsFacts(null, null, null, null, null, null, null);

  private static ConversationFacts flow(
      String client, int clientPort, String server, int serverPort, String proto, String app,
      LocalDateTime start) {
    return new ConversationFacts(
        UUID.randomUUID(), FILE,
        new FlowIdentity(client, clientPort, server, serverPort, client, clientPort, proto, 8, 900,
            start, start.plusNanos(20_000_000L)),
        NO_TLS,
        new Findings(app, null, null, List.of(), List.of(), List.of(), List.of()));
  }

  private List<StoryAggregates.BeaconCandidate> candidates(List<ConversationFacts> convs) {
    ConversationLookup lookup = mock(ConversationLookup.class);
    when(lookup.conversationFacts(FILE)).thenReturn(convs);
    // compute() computes several aggregates and swallows any failure into an EMPTY result, so an
    // unstubbed collaborator would make the beacon assertions pass or fail for the wrong reason.
    LocalityPolicy policy = mock(LocalityPolicy.class);
    when(policy.currentRules()).thenReturn(LocalityRules.RFC_ONLY);
    StoryAggregatesService service = new StoryAggregatesService(
        policy, lookup, mock(ExtractionManifest.class), mock(GeoOrgLookup.class));
    return service.compute(FILE, List.of(), convs.size()).getBeaconCandidates();
  }

  @Test
  void theDomainControllersKeepaliveIsNotACandidate_butARealExternalBeaconIs() {
    List<ConversationFacts> convs = new ArrayList<>();
    for (int i = 0; i < 5; i++) {
      // NetBIOS keepalive to the DC: exactly 30 s, four protocol views of one session
      for (String proto : new String[] {"TCP", "NBSS", "SMB", "LANMAN"}) {
        convs.add(flow("172.16.1.66", 50000 + i, "172.16.1.4", 139, proto, "NetBIOS", T0.plusSeconds(i * 30L)));
      }
      // a real beacon to an external host
      convs.add(flow("172.16.1.66", 51000 + i, "141.98.10.79", 12132, "TCP", "", T0.plusSeconds(i * 30L)));
    }

    List<StoryAggregates.BeaconCandidate> out = candidates(convs);

    // the real beacon appears (which also proves compute() did not fall back to its empty result)...
    assertThat(out).singleElement().satisfies(c -> {
      assertThat(c.getSrcIp()).isEqualTo("172.16.1.66");
      assertThat(c.getDstIp()).isEqualTo("141.98.10.79");
      assertThat(c.getDstPort()).isEqualTo(12132);
      assertThat(c.getFlowCount()).isEqualTo(5);
      assertThat(c.getAvgIntervalMs()).isEqualTo(30_000L);
    });
    // ...and the DC keepalive does not, once or four times
    assertThat(out).noneMatch(c -> "172.16.1.4".equals(c.getDstIp()));
  }

  @Test
  void oneSessionSeenAsSeveralProtocolViews_isOneCandidate_withTheViewsJoined() {
    List<ConversationFacts> convs = new ArrayList<>();
    for (int i = 0; i < 5; i++) {
      for (String proto : new String[] {"TCP", "SMB"}) {
        convs.add(flow("172.16.1.66", 50000 + i, "141.98.10.79", 12132, proto, "", T0.plusSeconds(i * 30L)));
      }
    }

    assertThat(candidates(convs)).singleElement()
        .satisfies(c -> assertThat(c.getProtocol()).contains("TCP").contains("SMB"));
  }
}
