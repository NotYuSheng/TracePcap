package com.tracepcap.knowledge.question;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.knowledge.contributor.DownloadContributor;
import com.tracepcap.knowledge.contributor.HoneypotContributor;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * How a honeypot changes other answers (docs/architecture/investigation-framework.rst): a decoy
 * isn't a victim, what it fetches is the catch, and whoever reaches it is the subject (#1330).
 */
class HoneypotFramingTest {

  private static final String DECOY = "198.51.100.22";
  private static final String REAL = "10.0.0.5";
  private static final String C2 = "203.0.113.9";

  private static Finding honeypot(String host, String name) {
    return new Finding(HoneypotContributor.HONEYPOT, host + " is a " + name, Severity.INFO,
        Grade.INFERRED, "honeypots", List.of(EntityRef.host(host)), List.of(),
        Map.of("host", host, "name", name, "basis", "MACHINE"));
  }

  private static Finding contact(String host, long conversations, Map<String, String> reached) {
    return new Finding(HoneypotContributor.CONTACT, host + " opened " + conversations + " conversations",
        Severity.MEDIUM, Grade.INFERRED, "honeypots", List.of(EntityRef.host(host)), List.of(),
        Map.of("host", host, "honeypots", reached, "conversations", conversations));
  }

  /** Two hosts that talk to one C2: a real one and a Cowrie decoy. */
  private static CaseKnowledgeBuilder c2Board() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external(C2);
    b.addRelationship(Relationship.of(c2, "c2-of", EntityRef.malware("Mirai"), Grade.INFERRED, "suricata"));
    b.addRelationship(Relationship.of(EntityRef.host(REAL), "communicates-with", c2, Grade.MEASURED, "traffic"));
    b.addRelationship(Relationship.of(EntityRef.host(DECOY), "communicates-with", c2, Grade.MEASURED, "traffic"));
    b.addFinding(honeypot(DECOY, "Cowrie honeypot"));
    return b;
  }

  @Test
  void aDecoyThatTalksToAC2IsNoVictim() {
    List<Answer> victims = new VictimQuestion().answer(c2Board().build());
    assertThat(victims).extracting(a -> a.subjects().get(0).key()).containsExactly(REAL);
  }

  @Test
  void aDecoyThatTalksToAC2IsTheAttackItRecorded() {
    List<Answer> a = new HoneypotActivityQuestion().answer(c2Board().build());
    assertThat(a).singleElement().satisfies(ans -> {
      assertThat(ans.question()).isEqualTo("honeypot-activity");
      assertThat(ans.headline()).isEqualTo(DECOY + ", a Cowrie honeypot, contacted the known C2 " + C2
          + ": the attack it was set up to record, not an infection");
      assertThat(ans.attributes()).containsEntry("decoy", "Cowrie honeypot").containsEntry("c2", List.of(C2));
      assertThat(ans.derivation()).extracting(s -> s.rule()).contains(Derivations.RULE_DECOY_C2);
    });
  }

  @Test
  void withNoHoneypotNothingChanges() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external(C2);
    b.addRelationship(Relationship.of(c2, "c2-of", EntityRef.malware("Mirai"), Grade.INFERRED, "suricata"));
    b.addRelationship(Relationship.of(EntityRef.host(DECOY), "communicates-with", c2, Grade.MEASURED, "traffic"));
    CaseKnowledge board = b.build();
    assertThat(new VictimQuestion().answer(board)).hasSize(1);
    assertThat(new HoneypotActivityQuestion().answer(board)).isEmpty();
  }

  @Test
  void whoeverReachedADecoyIsTheSubjectMostConversationsFirst() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    b.addFinding(honeypot(DECOY, "Cowrie honeypot"));
    b.addFinding(honeypot("198.51.100.45", "Dionaea honeypot"));
    b.addFinding(contact("198.51.100.103", 2, Map.of("198.51.100.45", "Dionaea honeypot")));
    Map<String, String> both = new LinkedHashMap<>();
    both.put("198.51.100.22", "Cowrie honeypot");
    both.put("198.51.100.45", "Dionaea honeypot");
    b.addFinding(contact("198.51.100.101", 9, both));
    List<Answer> a = new HoneypotActivityQuestion().answer(b.build());
    assertThat(a).extracting(ans -> ans.subjects().get(0).key())
        .containsExactly("198.51.100.101", "198.51.100.103");
    assertThat(a.get(0).headline()).isEqualTo("198.51.100.101 reached the Cowrie honeypot 198.51.100.22"
        + " and the Dionaea honeypot 198.51.100.45 (9 conversations): a decoy has no real users, so"
        + " this is scanning or an attack");
    assertThat(a.get(1).headline()).contains("(2 conversations)");
  }

  @Test
  void hostsThatReachedTheSameDecoysAreOneAnswer() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    b.addFinding(honeypot(DECOY, "Cowrie honeypot"));
    for (int i = 1; i <= 7; i++) b.addFinding(contact("192.0.2." + i, i, Map.of(DECOY, "Cowrie honeypot")));
    List<Answer> a = new HoneypotActivityQuestion().answer(b.build());
    assertThat(a).singleElement().satisfies(ans -> {
      assertThat(ans.headline()).isEqualTo("7 hosts (192.0.2.7, 192.0.2.6, 192.0.2.5, 192.0.2.4, 192.0.2.3"
          + " and 2 more) reached the Cowrie honeypot " + DECOY + " (28 conversations): a decoy has no"
          + " real users, so this is scanning or an attack");
      // Every host is a subject, the ones the headline only counts too.
      assertThat(ans.subjects()).hasSize(7).contains(EntityRef.host("192.0.2.1"));
    });
  }

  @Test
  void manyGroupsAreListedUpToTheCapThenCounted() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    for (int i = 1; i <= HoneypotActivityQuestion.MAX_GROUPS + 3; i++) {
      // each reaches its own decoy: one group apiece
      b.addFinding(honeypot("198.51.100." + i, "Cowrie honeypot"));
      b.addFinding(contact("192.0.2." + i, i, Map.of("198.51.100." + i, "Cowrie honeypot")));
    }
    List<Answer> a = new HoneypotActivityQuestion().answer(b.build());
    assertThat(a).hasSize(HoneypotActivityQuestion.MAX_GROUPS + 1);
    assertThat(a.get(0).subjects()).containsExactly(EntityRef.host("192.0.2.13"));
    assertThat(a.get(a.size() - 1).headline()).startsWith("3 more hosts reached a honeypot");
  }

  private static Finding download(String host) {
    Map<String, Object> attrs = new LinkedHashMap<>();
    attrs.put("host", host);
    attrs.put("external", C2);
    attrs.put("name", "mirai.arm7");
    attrs.put("mimeType", "application/x-executable");
    attrs.put("size", 120_000);
    attrs.put("url", "http://" + C2 + "/mirai.arm7");
    attrs.put("sha256", "ab" + host.hashCode());
    return new Finding(DownloadContributor.DOWNLOAD, host + " fetched mirai.arm7", Severity.MEDIUM,
        Grade.MEASURED, "downloads", List.of(EntityRef.host(host)), List.of("conv-" + host), attrs);
  }

  @Test
  void aFileADecoyFetchedIsTheCatchNotAnInfection() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    b.addFinding(honeypot(DECOY, "Cowrie honeypot"));
    b.addFinding(download(DECOY));
    b.addFinding(download(REAL));
    List<Answer> a = new DownloadsQuestion().answer(b.build());
    Answer decoy = a.stream().filter(x -> DECOY.equals(x.attributes().get("host"))).findFirst().orElseThrow();
    Answer real = a.stream().filter(x -> REAL.equals(x.attributes().get("host"))).findFirst().orElseThrow();
    assertThat(decoy.headline()).startsWith(DECOY + ", a Cowrie honeypot, caught mirai.arm7")
        .contains(": attacker tooling, not an infection. SHA-256 ");
    assertThat(decoy.attributes()).containsEntry("decoy", "Cowrie honeypot");
    assertThat(decoy.derivation()).extracting(s -> s.rule())
        .containsExactly(Derivations.RULE_DECOY_DOWNLOAD, Derivations.RULE_DOWNLOAD);
    assertThat(real.headline()).startsWith(REAL + " downloaded mirai.arm7");
    assertThat(real.attributes()).doesNotContainKey("decoy");
  }
}
