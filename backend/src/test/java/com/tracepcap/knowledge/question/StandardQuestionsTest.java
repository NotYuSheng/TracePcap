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
      assertThat(ans.attributes()).containsEntry("address", "141.98.10.79").containsEntry("malware", "STRRAT");
      assertThat(ans.subjects()).contains(EntityRef.external("141.98.10.79"), EntityRef.malware("STRRAT"));
    });
  }

  @Test
  void malware_listsTheNamedFamily() {
    List<Answer> a = new MalwareQuestion().answer(strratBoard());
    assertThat(a).singleElement().satisfies(ans -> assertThat(ans.attributes()).containsEntry("family", "STRRAT"));
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

  @Test
  void emptyBoard_yieldsNoAnswers() {
    CaseKnowledge empty = new CaseKnowledgeBuilder(UUID.randomUUID()).build();
    assertThat(new VictimQuestion().answer(empty)).isEmpty();
    assertThat(new C2Question().answer(empty)).isEmpty();
    assertThat(new MalwareQuestion().answer(empty)).isEmpty();
    assertThat(new SignedInUserQuestion().answer(empty)).isEmpty();
  }
}
