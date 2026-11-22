package com.tracepcap.knowledge.contributor;

import com.tracepcap.knowledge.spi.KnowledgeContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.Findings;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.analysis.spi.ConversationLookup.TlsFacts;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import com.tracepcap.knowledge.spi.Finding;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IdsAlertContributorTest {

  private static final UUID FILE = UUID.randomUUID();

  @Mock private ConversationLookup conversationLookup;

  private ConversationFacts conv(String src, String dst, List<String> suricata) {
    return new ConversationFacts(
        UUID.randomUUID(),
        FILE,
        new FlowIdentity(src, 49754, dst, 12132, src, 49754, "TCP", 411, 39064, null, null),
        new TlsFacts(null, null, null, null, null, null, null, null, null),
        new Findings(null, null, null, List.of(), suricata, List.of(), List.of()));
  }

  private CaseKnowledge run(ConversationFacts... convs) {
    when(conversationLookup.conversationFacts(FILE)).thenReturn(List.of(convs));
    CaseKnowledgeBuilder board = new CaseKnowledgeBuilder(FILE);
    new IdsAlertContributor().contribute(KnowledgeContext.of(FILE, conversationLookup, null), board);
    return board.build();
  }

  @Test
  void strratAlert_postsFindingExternalEntityC2EdgeAndMalware() {
    CaseKnowledge k =
        run(conv("172.16.1.66", "141.98.10.79",
            List.of("ET MALWARE STRRAT CnC Checkin (sid:2030358 sev:1)")));

    // ids-alert finding concerning both endpoints
    List<Finding> alerts = k.findingsOfCategory("ids-alert");
    assertThat(alerts).singleElement().satisfies(f -> {
      assertThat(f.summary()).contains("STRRAT");
      assertThat(f.concerns()).contains(EntityRef.host("172.16.1.66"), EntityRef.external("141.98.10.79"));
      assertThat(f.evidence()).hasSize(1); // the conversation id
    });

    // the external party is a service entity, and the malware family was parsed out
    assertThat(k.entitiesOfType(EntityType.EXTERNAL_SERVICE)).singleElement()
        .satisfies(e -> assertThat(e.key()).isEqualTo("141.98.10.79"));
    assertThat(k.entitiesOfType(EntityType.MALWARE)).singleElement()
        .satisfies(e -> assertThat(e.key()).isEqualTo("STRRAT"));

    // internal → external comms edge, and external → malware C2 edge
    assertThat(k.relationshipsWithPredicate("communicates-with")).singleElement()
        .satisfies(r -> {
          assertThat(r.from()).isEqualTo(EntityRef.host("172.16.1.66"));
          assertThat(r.to()).isEqualTo(EntityRef.external("141.98.10.79"));
        });
    assertThat(k.relationshipsWithPredicate("c2-of")).singleElement()
        .satisfies(r -> assertThat(r.from()).isEqualTo(EntityRef.external("141.98.10.79")));
  }

  @Test
  void genericMalwareToken_doesNotMintABogusFamilyOrC2() {
    // "ET MALWARE DNS Query ..." must NOT capture "DNS" as a malware family (which would create a
    // spurious malware entity + c2-of edge, mislabelling a benign server as a C2). The finding is
    // still recorded; there is just no family/C2 attribution.
    CaseKnowledge k =
        run(conv("172.16.1.66", "8.8.8.8",
            List.of("ET MALWARE DNS Query to a Suspicious Domain (sid:1 sev:2)")));

    assertThat(k.findingsOfCategory("ids-alert")).hasSize(1);
    assertThat(k.entitiesOfType(EntityType.MALWARE)).isEmpty();
    assertThat(k.relationshipsWithPredicate("c2-of")).isEmpty();
  }

  @Test
  void platformPrefixedFamily_extractsTheFamilyAfterTheSlash() {
    // "ET MALWARE MSIL/Ramnit ..." is a real malware C2 — keep the c2-of edge, but the family is
    // "Ramnit" (after the platform prefix), not the platform token "MSIL".
    CaseKnowledge k =
        run(conv("172.16.1.66", "141.98.10.79",
            List.of("ET MALWARE MSIL/Ramnit CnC Checkin (sid:9 sev:1)")));

    assertThat(k.entitiesOfType(EntityType.MALWARE)).singleElement()
        .satisfies(e -> assertThat(e.key()).isEqualTo("Ramnit"));
    assertThat(k.relationshipsWithPredicate("c2-of")).singleElement()
        .satisfies(r -> assertThat(r.from()).isEqualTo(EntityRef.external("141.98.10.79")));
  }

  @Test
  void internalToInternalAlert_recordsFindingButNoC2Direction() {
    // An IDS hit on internal↔internal traffic (both endpoints local) has no host↔external C2 pair —
    // it must not invent a communicates-with / c2-of edge (which would make one internal host a
    // "victim" of another internal host wrongly tagged a C2).
    CaseKnowledge k =
        run(conv("172.16.1.66", "172.16.1.4",
            List.of("ET MALWARE STRRAT CnC Checkin (sid:2030358 sev:1)")));

    assertThat(k.findingsOfCategory("ids-alert")).hasSize(1); // the alert itself is still recorded
    assertThat(k.relationshipsWithPredicate("communicates-with")).isEmpty();
    assertThat(k.relationshipsWithPredicate("c2-of")).isEmpty();
    assertThat(k.entitiesOfType(EntityType.MALWARE)).isEmpty();
  }

  @Test
  void conversationWithoutSuricataAlert_addsNothing() {
    CaseKnowledge k = run(conv("172.16.1.66", "8.8.8.8", List.of()));
    assertThat(k.findings()).isEmpty();
    assertThat(k.entities()).isEmpty();
  }

  @Test
  void directionIsInternalToExternal_regardlessOfWhichEndpointSortedFirst() {
    // external IP sorted as src; the C2 edge must still run internal → external
    CaseKnowledge k =
        run(conv("141.98.10.79", "172.16.1.66", List.of("ET MALWARE STRRAT CnC Checkin")));
    assertThat(k.relationshipsWithPredicate("communicates-with")).singleElement()
        .satisfies(r -> {
          assertThat(r.from()).isEqualTo(EntityRef.host("172.16.1.66"));
          assertThat(r.to()).isEqualTo(EntityRef.external("141.98.10.79"));
        });
  }

  // ── Family from the rule's malware_family tag ───────────────────────────────

  private static final com.tracepcap.analysis.spi.IdsRuleMetadata ET =
      sid ->
          java.util.Optional.ofNullable(
              java.util.Map.of(
                      2066606L, new com.tracepcap.analysis.spi.IdsRuleMetadata.RuleInfo(true, "Lumma Stealer"),
                      2052557L, new com.tracepcap.analysis.spi.IdsRuleMetadata.RuleInfo(true, "WARMCOOKIE"),
                      2052558L, new com.tracepcap.analysis.spi.IdsRuleMetadata.RuleInfo(true, null),
                      2059607L, new com.tracepcap.analysis.spi.IdsRuleMetadata.RuleInfo(true, null))
                  .get(sid));

  @Test
  void theRulesOwnTag_namesTheFamily_evenInMixedCase() {
    // The message reading missed this one: "Lumma Stealer" isn't all capitals.
    assertThat(new IdsAlertContributor(ET).malwareFamily(
            "ET MALWARE Lumma Stealer Victim Fingerprinting Activity (sid:2066606 sev:1)"))
        .isEqualTo("Lumma Stealer");
  }

  @Test
  void anAllCapsTag_takesTheMessagesSpelling() {
    assertThat(new IdsAlertContributor(ET).malwareFamily(
            "ET MALWARE BadSpace/WarmCookie CnC Activity (GET) M1 (sid:2052557 sev:1)"))
        .isEqualTo("WarmCookie");
  }

  @Test
  void aTaggedRuleWithoutAFamily_namesNone_ratherThanGuessing() {
    // Was a spurious "Badspace" next to WarmCookie, and a lure is not a family.
    IdsAlertContributor c = new IdsAlertContributor(ET);
    assertThat(c.malwareFamily("ET MALWARE W32/Badspace.Backdoor CnC Activity (POST) (sid:2052558 sev:1)")).isNull();
    assertThat(c.malwareFamily("ET MALWARE Fake Microsoft Teams CnC Payload Request (GET) (sid:2059607 sev:1)")).isNull();
  }

  @Test
  void aRuleTheRulesetDoesntKnow_fallsBackToTheMessage() {
    assertThat(new IdsAlertContributor(ET).malwareFamily("ET MALWARE STRRAT CnC Checkin (sid:9999999 sev:1)"))
        .isEqualTo("STRRAT");
  }

  // ── C2 without a named family ─────────────────────────────────────────────

  private CaseKnowledge runWithEt(ConversationFacts... convs) {
    when(conversationLookup.conversationFacts(FILE)).thenReturn(List.of(convs));
    CaseKnowledgeBuilder board = new CaseKnowledgeBuilder(FILE);
    new IdsAlertContributor(ET).contribute(KnowledgeContext.of(FILE, conversationLookup, null), board);
    return board.build();
  }

  private static List<com.tracepcap.knowledge.spi.Answer> answers(
      com.tracepcap.knowledge.spi.StandardQuestion q, CaseKnowledge k) {
    return q.answer(k);
  }

  @Test
  void aCncRuleWithoutAFamily_makesAnUnnamedC2_andItsVictim_butNoFamily() {
    // 2025-01-22 fake Google Authenticator: the only malware rule names no family.
    CaseKnowledge k =
        runWithEt(conv("10.1.17.215", "5.252.153.241",
            List.of("ET MALWARE Fake Microsoft Teams CnC Payload Request (GET) (sid:2059607 sev:1)")));
    assertThat(k.relationshipsWithPredicate("c2-of")).singleElement()
        .satisfies(r -> assertThat(r.to().key()).isEqualTo(EntityRef.UNIDENTIFIED_MALWARE));
    assertThat(answers(new com.tracepcap.knowledge.question.MalwareQuestion(), k)).isEmpty();
    assertThat(answers(new com.tracepcap.knowledge.question.C2Question(), k)).singleElement()
        .satisfies(a -> assertThat(a.headline()).contains("5.252.153.241").contains("unidentified malware"));
    assertThat(answers(new com.tracepcap.knowledge.question.VictimQuestion(), k)).singleElement()
        .satisfies(a -> assertThat(a.attributes().get("host")).isEqualTo("10.1.17.215"));
  }

  @Test
  void aFamilyLessC2Rule_besideANamedOne_addsNothing() {
    // 2024-08-15 WarmCookie: the POST rule has no family, the GET rule names WarmCookie.
    CaseKnowledge k =
        runWithEt(conv("10.8.15.133", "72.5.43.29", List.of(
            "ET MALWARE BadSpace/WarmCookie CnC Activity (GET) M1 (sid:2052557 sev:1)",
            "ET MALWARE W32/Badspace.Backdoor CnC Activity (POST) (sid:2052558 sev:1)")));
    assertThat(k.relationshipsWithPredicate("c2-of")).singleElement()
        .satisfies(r -> assertThat(r.to().key()).isEqualTo("WarmCookie"));
  }

  @Test
  void informationalAndReputationRules_neverMakeAC2() {
    CaseKnowledge k =
        runWithEt(
            conv("10.11.10.147", "93.152.209.36",
                List.of("ET INFO NetSupport Remote Admin Checkin (sid:2035892 sev:3)")),
            conv("10.1.17.215", "45.125.66.32",
                List.of("ET DROP Spamhaus DROP Listed Traffic Inbound group 7 (sid:2400006 sev:2)")));
    assertThat(k.relationshipsWithPredicate("c2-of")).isEmpty();
  }
}
