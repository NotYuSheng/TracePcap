package com.tracepcap.knowledge.question;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
import com.tracepcap.knowledge.spi.Step;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Each answer says how it was reached (#1293), on a board shaped like the STRRAT exercise
 * (2024-07-30): one rule names the C2, the victim talked to it, Kerberos names the user and LDAP
 * the person.
 */
class DerivationTest {

  private static final String VICTIM = "172.16.1.66", C2 = "141.98.10.79", CONV = "c0ffee00-0000-0000-0000-000000000001";
  private static final String RULE = "ET MALWARE STRRAT CnC Checkin (sid:2030358 sev:1)";

  private static CaseKnowledge strrat() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef host = EntityRef.host(VICTIM), c2 = EntityRef.external(C2), strrat = EntityRef.malware("STRRAT");
    b.addFinding(new Finding("ids-alert", RULE, Severity.CRITICAL, Grade.INFERRED, "suricata",
        List.of(host, c2), List.of(CONV), Map.of("srcIp", VICTIM, "dstIp", C2)));
    b.addRelationship(Relationship.of(host, "communicates-with", c2, Grade.MEASURED, "ids-alerts"));
    b.addRelationship(Relationship.of(c2, "c2-of", strrat, Grade.INFERRED, "suricata"));
    b.addEntity(c2, Map.of("country", "LT", "org", "UAB Host Baltic", "firstSeen", "2024-07-30T02:54:23Z"));
    b.addEntity(EntityRef.user("ccollier"), Map.of("source", "kerberos_as_req", "realName", "Clark Collier"));
    b.addRelationship(Relationship.of(host, "signed-in-as", EntityRef.user("ccollier"), Grade.MEASURED, "host-identity"));
    return b.build();
  }

  @Test
  void theC2_isARuleThatNamedIt_thenWhereItIsAndWhenItWasFirstReached() {
    Answer a = new C2Question().answer(strrat()).get(0);
    Step rule = a.derivation().get(0);
    assertThat(rule.found()).isEqualTo("Suricata rule \"" + RULE + "\" fired on " + VICTIM + " → " + C2 + ".");
    assertThat(rule.rule()).isEqualTo(Derivations.RULE_NAMED_C2);
    assertThat(rule.conversations()).containsExactly(CONV);
    assertThat(a.derivation()).extracting(Step::found)
        .anySatisfy(s -> assertThat(s).contains("UAB Host Baltic in LT").contains("GeoIP"))
        .anySatisfy(s -> assertThat(s).startsWith("First contacted at 2024-07-30 02:54:23 UTC"));
    // Context steps carry no rule: they describe, they don't conclude.
    assertThat(a.derivation().subList(1, a.derivation().size())).allSatisfy(s -> assertThat(s.rule()).isNull());
  }

  @Test
  void theVictim_followsFromTheC2_andTalkingToIt() {
    Answer a = new VictimQuestion().answer(strrat()).get(0);
    assertThat(a.derivation()).hasSize(3);
    assertThat(a.derivation().get(0).found()).startsWith(C2 + " is a command-and-control server for STRRAT");
    assertThat(a.derivation().get(1).found()).isEqualTo(VICTIM + " talked to " + C2 + ".");
    assertThat(a.derivation().get(1).rule()).isEqualTo(Derivations.RULE_VICTIM);
    assertThat(a.derivation().get(1).conversations()).containsExactly(CONV);
    assertThat(a.derivation().get(2).found()).contains("signed in as ccollier");
  }

  @Test
  void theUser_isItsOwnKerberosSignIn_andTheDirectoryNamesThePerson() {
    Answer a = new SignedInUserQuestion().answer(strrat()).get(0);
    assertThat(a.derivation().get(0).found()).isEqualTo(VICTIM + " identified itself as ccollier in its own Kerberos AS-REQ.");
    assertThat(a.derivation().get(0).rule()).isEqualTo(Derivations.RULE_KERBEROS_SIGN_IN);
    assertThat(a.derivation().get(0).grade()).isEqualTo(Grade.MEASURED);
    assertThat(a.derivation().get(1).found()).contains("Clark Collier");
    assertThat(a.derivation().get(1).grade()).isEqualTo(Grade.REPORTED);
  }

  @Test
  void theFamily_isTheRuleThatNamedIt() {
    Answer a = new MalwareQuestion().answer(strrat()).get(0);
    assertThat(a.derivation()).singleElement().satisfies(s -> {
      assertThat(s.found()).isEqualTo("Suricata rule \"" + RULE + "\" fired.");
      assertThat(s.rule()).isEqualTo(Derivations.RULE_FAMILY);
      assertThat(s.conversations()).containsExactly(CONV);
    });
  }

  @Test
  void eachHostsSignIn_isNamedByItsOwnMethod_notTheLastHosts() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    b.addEntity(EntityRef.user("ccollier"), Map.of("source", "ldap_dn")); // the last host's
    b.addRelationship(new Relationship(EntityRef.host("10.0.0.1"), "signed-in-as", EntityRef.user("ccollier"),
        Grade.MEASURED, "host-identity", Map.of("signInSource", "kerberos_as_req")));
    b.addRelationship(new Relationship(EntityRef.host("10.0.0.2"), "signed-in-as", EntityRef.user("ccollier"),
        Grade.REPORTED, "host-identity", Map.of("signInSource", "ldap_dn")));
    List<Answer> answers = new SignedInUserQuestion().answer(b.build());
    assertThat(answers).filteredOn(a -> "10.0.0.1".equals(a.attributes().get("host"))).singleElement()
        .satisfies(a -> assertThat(a.derivation().get(0).rule()).isEqualTo(Derivations.RULE_KERBEROS_SIGN_IN));
    assertThat(answers).filteredOn(a -> "10.0.0.2".equals(a.attributes().get("host"))).singleElement()
        .satisfies(a -> assertThat(a.derivation().get(0).rule()).isEqualTo(Derivations.RULE_LDAP_SIGN_IN));
  }

  @Test
  void aVictimsReportedSignIn_staysReportedInItsSteps() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef host = EntityRef.host(VICTIM), c2 = EntityRef.external(C2);
    b.addRelationship(Relationship.of(host, "communicates-with", c2, Grade.MEASURED, "ids-alerts"));
    b.addRelationship(Relationship.of(c2, "c2-of", EntityRef.malware("STRRAT"), Grade.INFERRED, "suricata"));
    b.addRelationship(Relationship.of(host, "signed-in-as", EntityRef.user("ccollier"), Grade.REPORTED, "host-identity"));
    Answer a = new VictimQuestion().answer(b.build()).get(0);
    assertThat(a.derivation().get(a.derivation().size() - 1).grade()).isEqualTo(Grade.REPORTED);
  }

  @Test
  void aCorroborationWithoutAReason_stillAnswers_andIsNoDetectorsIdentification() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    EntityRef c2 = EntityRef.external("45.1.2.3");
    b.addRelationship(new Relationship(c2, "c2-of", EntityRef.malware("STRRAT"), Grade.INFERRED, "corroboration",
        Map.of("corroboration", "suspected-c2", "reason", " ")));
    b.addFinding(new Finding("c2-classification", "STRRAT suspected: listed and reached in rounds", Severity.HIGH,
        Grade.INFERRED, "corroboration", List.of(c2), List.of(), Map.of()));
    CaseKnowledge board = b.build();
    assertThat(new C2Question().answer(board)).singleElement()
        .satisfies(a -> assertThat(a.derivation().get(0).found()).contains("corroborated as a C2"));
    assertThat(new MalwareQuestion().answer(board)).singleElement()
        .satisfies(a -> assertThat(a.derivation()).isEmpty());
  }

  @Test
  void aStepNamesEachConversationOnce() {
    assertThat(new Step("x", null, Grade.MEASURED, List.of("a", "b", "a")).conversations()).containsExactly("a", "b");
  }
}
