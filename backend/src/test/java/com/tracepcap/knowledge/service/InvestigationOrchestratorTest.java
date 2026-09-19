package com.tracepcap.knowledge.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.knowledge.question.C2Question;
import com.tracepcap.knowledge.question.MalwareQuestion;
import com.tracepcap.knowledge.question.SignedInUserQuestion;
import com.tracepcap.knowledge.question.VictimQuestion;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Goal;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.InvestigationReport;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The L2 orchestrator (#819) is pure board-in / report-out, so it is tested with no file or DB —
 * the {@code report(...)} seam takes an assembled board and the answers a run would produce.
 */
class InvestigationOrchestratorTest {

  private static final UUID FILE = UUID.randomUUID();

  private final InvestigationOrchestrator service = new InvestigationOrchestrator(null, null);
  private final StandardQuestionService questions =
      new StandardQuestionService(
          null, List.of(new VictimQuestion(), new C2Question(), new MalwareQuestion(),
              new SignedInUserQuestion()));

  /** The STRRAT facts the contributors would post, with their real source labels. */
  private CaseKnowledge strratBoard() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(FILE);
    EntityRef host = EntityRef.host("172.16.1.66");
    EntityRef user = EntityRef.user("ccollier");
    EntityRef c2 = EntityRef.external("141.98.10.79");
    EntityRef strrat = EntityRef.malware("STRRAT");
    b.addRelationship(Relationship.of(host, "signed-in-as", user, Grade.MEASURED, "host-identity"));
    b.addRelationship(Relationship.of(host, "communicates-with", c2, Grade.MEASURED, "ids-alerts"));
    b.addRelationship(Relationship.of(c2, "c2-of", strrat, Grade.INFERRED, "suricata"));
    b.addFinding(new Finding("ids-alert", "ET MALWARE STRRAT CnC Checkin", Severity.CRITICAL,
        Grade.INFERRED, "suricata", List.of(host, c2), List.of("conv-1"), null));
    return b.build();
  }

  private InvestigationReport investigate(CaseKnowledge board) {
    return service.report(FILE, board, questions.answer(board));
  }

  @Test
  void closesEveryGoal_withConfidenceFromGrade_andNoUnknowns() {
    InvestigationReport report = investigate(strratBoard());

    assertThat(report.outcomes()).extracting(o -> o.goal()).containsExactly(Goal.values());
    assertThat(report.outcomes()).allSatisfy(o -> assertThat(o.answered()).isTrue());
    assertThat(report.openGoals()).isEmpty();

    // signed-in user is MEASURED (Kerberos) -> highest confidence; the IDS-derived goals are INFERRED
    assertThat(outcome(report, Goal.USER).confidence()).isEqualTo(90);
    assertThat(outcome(report, Goal.C2).confidence()).isEqualTo(55);
    assertThat(outcome(report, Goal.C2).headline()).contains("141.98.10.79");
  }

  @Test
  void reportsCoverage_asTheTechniquesThatContributed() {
    assertThat(investigate(strratBoard()).coverage())
        .contains("host-identity", "ids-alerts", "suricata");
  }

  @Test
  void openGoalsAreSurfacedAsUnknowns_notHidden() {
    // A board that only knows the signed-in user: victim/C2/malware cannot be closed.
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(FILE);
    b.addRelationship(Relationship.of(EntityRef.host("172.16.1.66"), "signed-in-as",
        EntityRef.user("ccollier"), Grade.MEASURED, "host-identity"));

    InvestigationReport report = investigate(b.build());

    assertThat(outcome(report, Goal.USER).answered()).isTrue();
    assertThat(report.openGoals()).containsExactlyInAnyOrder(Goal.VICTIM, Goal.MALWARE, Goal.C2);
    assertThat(outcome(report, Goal.MALWARE).headline()).isNull();
    assertThat(outcome(report, Goal.MALWARE).confidence()).isZero();
  }

  private static InvestigationReport.GoalOutcome outcome(InvestigationReport r, Goal g) {
    return r.outcomes().stream().filter(o -> o.goal() == g).findFirst().orElseThrow();
  }

  @Test
  void emptyBoard_leavesEveryGoalOpen() {
    List<Answer> none = List.of();
    InvestigationReport report = service.report(FILE, new CaseKnowledgeBuilder(FILE).build(), none);
    assertThat(report.openGoals()).containsExactly(Goal.values());
    assertThat(report.coverage()).isEmpty();
  }
}
