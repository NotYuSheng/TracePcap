package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.Findings;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.analysis.spi.ConversationLookup.TlsFacts;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Shaped on the 2025-01-22 fake software site and 2026-11-10 NetSupport training captures. */
class C2CorroborationTest {

  private static final LocalDateTime T0 = LocalDateTime.of(2025, 1, 22, 19, 45, 56);
  private static final String DROP = "ET DROP Spamhaus DROP Listed Traffic Inbound group 7 (sid:2400006 sev:2)";

  /** host -> external at T0 + seconds; received = bytes the host received. */
  private static ConversationFacts c(String host, String ext, long seconds, String name, long received, String... alerts) {
    LocalDateTime t = T0.plusSeconds(seconds);
    return new ConversationFacts(
        UUID.randomUUID(), UUID.randomUUID(),
        new FlowIdentity(host, 50000, ext, 443, host, 50000, "TLSV1.2", 10, received + 1000, t, t.plusSeconds(5),
            null, null, "ANSWERED", "TCP", 1000L, received),
        new TlsFacts(name, null, null, null, null, null, null, null, null),
        new Findings(null, null, null, List.of(), List.of(alerts), List.of(), List.of()));
  }

  private static List<ConversationFacts> fakeSite(boolean infected) {
    List<ConversationFacts> l = new ArrayList<>();
    if (infected) l.add(c("10.1.17.215", "5.252.153.241", 0, null, 945, "ET MALWARE Fake Microsoft Teams CnC Payload Request (GET) (sid:2059607 sev:1)"));
    for (long round : new long[] {830, 2360, 2525}) { // 19:59:46, 20:25:16, 20:28:01
      l.add(c("10.1.17.215", "45.125.66.32", round, "45.125.66.32", 2_700_000, DROP));
      l.add(c("10.1.17.215", "45.125.66.32", round + 13, "45.125.66.32", 8_000));
      l.add(c("10.1.17.215", "45.125.66.252", round + 27, null, 43_000, DROP));
    }
    return l;
  }

  @Test
  void reputationListedServersInScriptedRounds_fromAnInfectedHost_areSuspectedC2s() {
    List<C2Corroboration.Escalation> e = C2Corroboration.find(fakeSite(true), Set.of("5.252.153.241"));
    assertThat(e).extracting(C2Corroboration.Escalation::external).containsExactlyInAnyOrder("45.125.66.32", "45.125.66.252");
    assertThat(e).allSatisfy(x -> {
      assertThat(x.kind()).isEqualTo(C2Corroboration.SUSPECTED);
      assertThat(x.family()).isNull();
      assertThat(x.reason()).contains("Spamhaus DROP").contains("already talking to a confirmed C2");
    });
    assertThat(e).filteredOn(x -> x.external().equals("45.125.66.32"))
        .singleElement().satisfies(x -> assertThat(x.reason()).contains("3 separate rounds"));
    assertThat(e).filteredOn(x -> x.external().equals("45.125.66.252"))
        .singleElement().satisfies(x -> assertThat(x.reason()).contains("3 separate rounds"));
  }

  @Test
  void aServerContactedOnce_secondsAfterARepeatingOne_isPartOfItsRound() {
    List<ConversationFacts> l = new ArrayList<>(fakeSite(true).subList(0, 1));
    for (long round : new long[] {830, 2360}) l.add(c("10.1.17.215", "45.125.66.32", round, null, 2_700_000, DROP));
    l.add(c("10.1.17.215", "45.125.66.99", 2385, null, 40_000, DROP)); // once, 25 s after round 2
    assertThat(C2Corroboration.find(l, Set.of("5.252.153.241")))
        .filteredOn(x -> x.external().equals("45.125.66.99"))
        .singleElement().satisfies(x -> assertThat(x.reason()).contains("seconds after 45.125.66.32"));
  }

  @Test
  void reputationAlone_onAHostWithNoConfirmedC2_isNotEnough() {
    assertThat(C2Corroboration.find(fakeSite(false), Set.of())).isEmpty();
  }

  @Test
  void oneVisit_orANamedServer_isNotEnough() {
    List<ConversationFacts> l = new ArrayList<>(fakeSite(true).subList(0, 1));
    l.add(c("10.1.17.215", "45.125.66.40", 900, null, 5_000, DROP)); // once only
    l.add(c("10.1.17.215", "45.125.66.41", 900, "cdn.example.com", 5_000, DROP)); // has a name
    l.add(c("10.1.17.215", "45.125.66.41", 2400, "cdn.example.com", 5_000, DROP));
    assertThat(C2Corroboration.find(l, Set.of("5.252.153.241"))).isEmpty();
  }

  // ── Install chain ─────────────────────────────────────────────────────────

  private static List<ConversationFacts> netSupport(long scriptAt, long payloadBytes, String checkInName) {
    List<ConversationFacts> l = new ArrayList<>();
    l.add(c("10.11.10.147", "96.62.224.200", scriptAt, "vericheckusgo.com", 17_120,
        "ET INFO Windows Powershell User-Agent Usage (sid:2033355 sev:3)"));
    l.add(c("10.11.10.147", "96.62.224.200", scriptAt + 9, null, payloadBytes));
    l.add(c("10.11.10.147", "93.152.209.36", 18, checkInName, 7_450,
        "ET POLICY HTTP traffic on port 443 (POST) (sid:2013926 sev:2)",
        "ET INFO NetSupport Remote Admin Checkin (sid:2035892 sev:3)"));
    return l;
  }

  @Test
  void aScriptThenAPayloadThenNetSupportToABareIp_isAProbableRat() {
    assertThat(C2Corroboration.find(netSupport(0, 6_279_017, null), Set.of()))
        .singleElement()
        .satisfies(x -> {
          assertThat(x.external()).isEqualTo("93.152.209.36");
          assertThat(x.family()).isEqualTo("NetSupport RAT");
          assertThat(x.kind()).isEqualTo(C2Corroboration.INSTALL_CHAIN);
          assertThat(x.reason()).contains("vericheckusgo.com (96.62.224.200)").contains("6.3 MB")
              .contains("9 seconds later NetSupport");
        });
  }

  @Test
  void withoutTheChain_itStaysARemoteAccessTool() {
    assertThat(C2Corroboration.find(netSupport(-1800, 6_279_017, null), Set.of())).isEmpty(); // 30 min earlier
    assertThat(C2Corroboration.find(netSupport(0, 200_000, null), Set.of())).isEmpty(); // no big payload
    assertThat(C2Corroboration.find(netSupport(0, 6_279_017, "gw.it-company.example"), Set.of())).isEmpty(); // named gateway
  }

  @Test
  void curlFetchingAPayload_isAnInstallChainToo() {
    List<ConversationFacts> l = new ArrayList<>();
    l.add(c("10.10.1.128", "107.175.82.242", 0, "107.175.82.242", 1_600_000,
        "ET HUNTING curl User-Agent to Dotted Quad (sid:2034567 sev:2)",
        "ET INFO Executable Download from dotted-quad Host (sid:2016141 sev:2)"));
    l.add(c("10.10.1.128", "51.89.1.1", 40, null, 9_000, "ET INFO NetSupport Remote Admin Checkin (sid:1 sev:3)"));
    assertThat(C2Corroboration.find(l, Set.of())).singleElement()
        .satisfies(x -> assertThat(x.family()).isEqualTo("NetSupport RAT"));
  }

  @Test
  void anAdminToolsInstallChain_isNotACommandAndControl() {
    // PowerShell fetching AnyDesk's installer, then AnyDesk checking in, is also IT installing it.
    List<ConversationFacts> l = new ArrayList<>();
    l.add(c("10.10.1.128", "107.175.82.242", 0, "107.175.82.242", 1_600_000,
        "ET HUNTING curl User-Agent to Dotted Quad (sid:2034567 sev:2)"));
    l.add(c("10.10.1.128", "51.89.1.1", 40, null, 9_000, "ET INFO AnyDesk Remote Desktop Software User-Agent (sid:1 sev:3)"));
    assertThat(C2Corroboration.find(l, Set.of())).isEmpty();
  }

  @Test
  void whatTheRuleRuledOut_saysWhichRequirementItFailed() {
    // #1294: the same three misses as above, now with their reasons rather than silence.
    List<ConversationFacts> l = new ArrayList<>(fakeSite(true).subList(0, 1));
    l.add(c("10.1.17.215", "45.125.66.40", 900, null, 5_000, DROP)); // once only
    l.add(c("10.1.17.215", "45.125.66.41", 900, "cdn.example.com", 5_000, DROP)); // has a name
    l.add(c("10.1.17.216", "45.125.66.42", 900, null, 5_000, DROP)); // a host with no confirmed C2
    C2Corroboration.Analysis a = C2Corroboration.analyse(l, Set.of("5.252.153.241"));
    assertThat(a.escalations()).isEmpty();
    assertThat(a.rejections()).extracting(C2Corroboration.Rejection::external, C2Corroboration.Rejection::reason)
        .containsExactlyInAnyOrder(
            org.assertj.core.groups.Tuple.tuple("45.125.66.40", "reached in one round, not in repeated rounds or seconds after a server that was"),
            org.assertj.core.groups.Tuple.tuple("45.125.66.41", "it was reached by name, not as a bare IP"),
            org.assertj.core.groups.Tuple.tuple("45.125.66.42", "10.1.17.216 never talked to a confirmed C2, so nothing says it is infected"));
    assertThat(a.rejections()).allSatisfy(r -> {
      assertThat(r.listedBy()).isEqualTo("Spamhaus DROP");
      assertThat(r.conversations()).isNotEmpty();
    });
  }

  @Test
  void aServerTheRuleEscalated_isNotAlsoRuledOut() {
    C2Corroboration.Analysis a = C2Corroboration.analyse(fakeSite(true), Set.of("5.252.153.241"));
    assertThat(a.rejections()).isEmpty();
  }
}
