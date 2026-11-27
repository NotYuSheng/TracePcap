package com.tracepcap.knowledge.question;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.knowledge.service.StandardQuestionService;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Exercises the deterministic question catalog against a fixture board mirroring the STRRAT case —
 * the exact scenario Story mode got wrong. These are pure board-in / answer-out, no LLM.
 */
class StandardQuestionsTest {

  /** Board holding the STRRAT facts the two contributors would post. */
  private CaseKnowledge strratBoard() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef host = EntityRef.host("172.16.1.66");
    EntityRef user = EntityRef.user("ccollier");
    EntityRef c2 = EntityRef.external("141.98.10.79");
    EntityRef strrat = EntityRef.malware("STRRAT");
    b.addRelationship(Relationship.of(host, "signed-in-as", user, Grade.MEASURED, "host-identity"));
    b.addRelationship(Relationship.of(host, "communicates-with", c2, Grade.MEASURED, "ids-alerts"));
    b.addRelationship(Relationship.of(c2, "c2-of", strrat, Grade.INFERRED, "suricata"));
    b.addFinding(new Finding("ids-alert", "ET MALWARE STRRAT CnC Checkin (sid:2030358 sev:1)",
        Severity.CRITICAL, Grade.INFERRED, "suricata", List.of(host, c2), List.of("conv-1"), null));
    return b.build();
  }

  @Test
  void victim_isTheHostAnAlertConcerns_enrichedWithItsUser() {
    List<Answer> a = new VictimQuestion().answer(strratBoard());
    assertThat(a).singleElement().satisfies(ans -> {
      assertThat(ans.subjects()).containsExactly(EntityRef.host("172.16.1.66"));
      assertThat(ans.attributes()).containsEntry("signedInUser", "ccollier");
      assertThat(ans.headline()).contains("172.16.1.66").contains("ccollier");
    });
  }

  @Test
  void c2_isTheExternalEndpoint_withMalwareFamily() {
    List<Answer> a = new C2Question().answer(strratBoard());
    assertThat(a).singleElement().satisfies(ans -> {
      assertThat(ans.attributes())
          .containsEntry("address", "141.98.10.79")
          .containsEntry("malware", List.of("STRRAT")) // always a list, single family included
          .containsEntry("conclusion", "rule") // a malware rule named it: no corroboration chip
          .doesNotContainKey("conclusionReason");
      assertThat(ans.subjects()).contains(EntityRef.external("141.98.10.79"), EntityRef.malware("STRRAT"));
    });
  }

  @Test
  void c2_includesGeoAttribution_whenTheExternalEntityCarriesIt() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external("141.98.10.79");
    EntityRef strrat = EntityRef.malware("STRRAT");
    b.addEntity(c2, java.util.Map.of("country", "LT", "org", "UAB Host Baltic"));
    b.addRelationship(Relationship.of(c2, "c2-of", strrat, Grade.INFERRED, "suricata"));

    List<Answer> a = new C2Question().answer(b.build());
    assertThat(a).singleElement().satisfies(ans -> {
      assertThat(ans.headline()).contains("LT · UAB Host Baltic");
      assertThat(ans.attributes()).containsEntry("country", "LT").containsEntry("org", "UAB Host Baltic");
    });
  }

  @Test
  void c2_dedupesAFamilyNamedByMultipleRules() {
    // Two rules on one conversation both name STRRAT → two identical c2-of edges. The answer must
    // list the family once, not "STRRAT, STRRAT" with a duplicate subject.
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external("141.98.10.79");
    EntityRef strrat = EntityRef.malware("STRRAT");
    b.addRelationship(Relationship.of(c2, "c2-of", strrat, Grade.INFERRED, "suricata"));
    b.addRelationship(Relationship.of(c2, "c2-of", strrat, Grade.INFERRED, "suricata"));

    List<Answer> a = new C2Question().answer(b.build());
    assertThat(a).singleElement().satisfies(ans -> {
      assertThat(ans.headline()).contains("C2 for STRRAT").doesNotContain("STRRAT, STRRAT");
      assertThat(ans.attributes()).containsEntry("malware", List.of("STRRAT"));
      assertThat(ans.subjects()).containsExactly(c2, strrat);
    });
  }

  @Test
  void c2AndMalware_useTheStreamClassificationAsBasis_whenNoIdsAlertFired() {
    // Suricata off: the only evidence is the classifier's finding. The answers must still say why.
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external("141.98.10.79");
    EntityRef strrat = EntityRef.malware("STRRAT");
    b.addRelationship(Relationship.of(c2, "c2-of", strrat, Grade.INFERRED, "stream-classifier"));
    b.addFinding(new Finding("c2-classification",
        "STRRAT C2 identified from the beacon's cleartext check-in (matched the STRRAT protocol fingerprint in the stream to 141.98.10.79)",
        Severity.HIGH, Grade.INFERRED, "stream-classifier", List.of(c2, strrat), List.of("conv-1"), null));
    CaseKnowledge board = b.build();

    assertThat(new C2Question().answer(board)).singleElement()
        .satisfies(ans -> assertThat(ans.basis()).singleElement().satisfies(s -> assertThat(s).contains("cleartext")));
    assertThat(new MalwareQuestion().answer(board)).singleElement()
        .satisfies(ans -> assertThat(ans.basis()).singleElement().satisfies(s -> assertThat(s).contains("STRRAT")));
  }

  @Test
  void malware_listsTheNamedFamily() {
    List<Answer> a = new MalwareQuestion().answer(strratBoard());
    assertThat(a).singleElement().satisfies(ans -> assertThat(ans.attributes()).containsEntry("family", "STRRAT"));
  }

  @Test
  void signedInUser_includesTheLdapRealName_whenTheUserEntityCarriesIt() {
    // host-identity posts the LDAP display name as a USER attribute; the answer names both.
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef host = EntityRef.host("172.16.1.66");
    EntityRef user = EntityRef.user("ccollier");
    b.addEntity(user, java.util.Map.of("realName", "Clark Collier"));
    b.addRelationship(Relationship.of(host, "signed-in-as", user, Grade.MEASURED, "host-identity"));

    assertThat(new SignedInUserQuestion().answer(b.build())).singleElement().satisfies(ans -> {
      assertThat(ans.headline()).isEqualTo("ccollier (Clark Collier) signed in on 172.16.1.66");
      assertThat(ans.attributes())
          .containsEntry("user", "ccollier").containsEntry("realName", "Clark Collier");
    });
  }

  @Test
  void signedInUser_carriesTheEdgeGrade() {
    List<Answer> a = new SignedInUserQuestion().answer(strratBoard());
    assertThat(a).singleElement().satisfies(ans -> {
      assertThat(ans.grade()).isEqualTo(Grade.MEASURED); // Kerberos
      assertThat(ans.attributes()).containsEntry("user", "ccollier").containsEntry("host", "172.16.1.66");
    });
  }

  @Test
  void runner_aggregatesEveryQuestionsAnswers() {
    StandardQuestionService service = new StandardQuestionService(
        null,
        List.of(new VictimQuestion(), new C2Question(), new MalwareQuestion(), new SignedInUserQuestion()));

    List<Answer> answers = service.answer(strratBoard());

    assertThat(answers).extracting(Answer::question)
        .containsExactlyInAnyOrder("victim", "c2", "malware", "signed-in-user");
  }

  /** A host→external communicates-with edge with a byte count and the external's org on the board. */
  private CaseKnowledge transferBoard(long bytes, String org) {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef host = EntityRef.host("172.16.1.66");
    EntityRef ext = EntityRef.external("199.232.196.209");
    b.addEntity(ext, java.util.Map.of("org", org, "country", "US"));
    b.addRelationship(new Relationship(host, "communicates-with", ext, Grade.MEASURED, "traffic",
        java.util.Map.of("bytes", bytes)));
    return b.build();
  }

  @Test
  void dataTransfer_flagsBulkTransferToNonCdnExternal() {
    List<Answer> a = new DataTransferQuestion().answer(transferBoard(8_000_000L, "UAB Host Baltic"));
    assertThat(a).singleElement().satisfies(ans -> {
      assertThat(ans.headline()).contains("199.232.196.209").contains("7.63 MB").contains("UAB Host Baltic");
      assertThat(ans.attributes()).containsEntry("bytes", 8_000_000L);
    });
  }

  @Test
  void dataTransfer_excludesCdnAndCloudOrgs() {
    // The exact false positive the LLM made on the demo: a big Fastly CDN transfer is NOT a finding.
    assertThat(new DataTransferQuestion().answer(transferBoard(8_000_000L, "Fastly, Inc."))).isEmpty();
    assertThat(new DataTransferQuestion().answer(transferBoard(8_000_000L, "Amazon.com, Inc."))).isEmpty();
  }

  @Test
  void dataTransfer_cdnExclusionMatchesWholeWordsNotSubstrings() {
    // "Kaws Networks" contains the substring "aws" but is not AWS — a genuine destination that must
    // still be surfaced, not silently dropped by an over-broad substring match.
    assertThat(new DataTransferQuestion().answer(transferBoard(8_000_000L, "Kaws Networks"))).hasSize(1);
    // "Level 3 Communications" is backbone/CDN transit — excluded despite the embedded space.
    assertThat(new DataTransferQuestion().answer(transferBoard(8_000_000L, "Level 3 Communications"))).isEmpty();
    // A VPS/IaaS host (DigitalOcean) is NOT a CDN — it routinely fronts C2/exfil, so it must surface.
    assertThat(new DataTransferQuestion().answer(transferBoard(8_000_000L, "DigitalOcean, LLC"))).hasSize(1);
  }

  @Test
  void dataTransfer_ignoresTransfersBelowTheBulkThreshold() {
    assertThat(new DataTransferQuestion().answer(transferBoard(1_000_000L, "UAB Host Baltic"))).isEmpty();
  }

  @Test
  void emptyBoard_yieldsNoAnswers() {
    CaseKnowledge empty = new CaseKnowledgeBuilder(UUID.randomUUID()).build();
    assertThat(new VictimQuestion().answer(empty)).isEmpty();
    assertThat(new C2Question().answer(empty)).isEmpty();
    assertThat(new MalwareQuestion().answer(empty)).isEmpty();
    assertThat(new SignedInUserQuestion().answer(empty)).isEmpty();
    assertThat(new DataTransferQuestion().answer(empty)).isEmpty();
  }

  // ── Direction (a download is not exfiltration) ──────────────────────────────

  private CaseKnowledge directionalBoard(long sent, long received) {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef host = EntityRef.host("10.11.10.147");
    EntityRef ext = EntityRef.external("96.62.224.200");
    b.addEntity(ext, java.util.Map.of("org", "Some Hosting", "country", "DE"));
    b.addRelationship(new Relationship(host, "communicates-with", ext, Grade.MEASURED, "traffic",
        java.util.Map.of("bytes", sent + received, "sentBytes", sent, "receivedBytes", received)));
    return b.build();
  }

  @Test
  void dataTransfer_aLargeDownload_isNotFlagged() {
    // 2026-11-10: the host received a 6 MB file (5555.mp4); it used to read "sent 6.3 MB".
    assertThat(new DataTransferQuestion().answer(directionalBoard(200_000L, 6_100_000L))).isEmpty();
  }

  @Test
  void dataTransfer_aLargeUpload_isFlagged_asSent() {
    assertThat(new DataTransferQuestion().answer(directionalBoard(7_000_000L, 300_000L)))
        .singleElement()
        .satisfies(ans -> assertThat(ans.headline()).contains("10.11.10.147 sent 6.68 MB"));
  }

  @Test
  void dataTransfer_withoutDirection_saysExchanged() {
    assertThat(new DataTransferQuestion().answer(transferBoard(8_000_000L, "UAB Host Baltic")))
        .singleElement()
        .satisfies(ans -> assertThat(ans.headline()).contains("exchanged 7.63 MB with "));
  }

  @Test
  void c2_saysHowACorroboratedServerWasConcluded() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external("45.1.2.3");
    b.addRelationship(new Relationship(c2, "c2-of", EntityRef.malware(EntityRef.UNIDENTIFIED_MALWARE),
        Grade.INFERRED, "corroboration",
        java.util.Map.of("corroboration", "suspected-c2", "reason", "ET DROP listed; 4 rounds")));
    assertThat(new C2Question().answer(b.build())).singleElement().satisfies(ans ->
        assertThat(ans.attributes())
            .containsEntry("conclusion", "suspected-c2")
            .containsEntry("conclusionReason", "ET DROP listed; 4 rounds"));
  }

  @Test
  void c2_theChipNamesTheStrongestConclusion_asTheHeadlineDoes() {
    // Suspected first, then an install chain: not worded "suspected", so not chipped "Suspected".
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external("45.1.2.3");
    b.addRelationship(new Relationship(c2, "c2-of", EntityRef.malware(EntityRef.UNIDENTIFIED_MALWARE),
        Grade.INFERRED, "corroboration", java.util.Map.of("corroboration", "suspected-c2", "reason", "listed")));
    b.addRelationship(new Relationship(c2, "c2-of", EntityRef.malware("NetSupport RAT"),
        Grade.INFERRED, "corroboration", java.util.Map.of("corroboration", "install-chain", "reason", "chain")));
    assertThat(new C2Question().answer(b.build())).singleElement().satisfies(ans -> {
      assertThat(ans.headline()).doesNotContain("suspected");
      assertThat(ans.attributes()).containsEntry("conclusion", "install-chain");
    });
  }
}
