package com.tracepcap.insights.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.tracepcap.common.event.AnalysisCompletedEvent;
import com.tracepcap.common.stage.Adjudicator;
import com.tracepcap.common.stage.Tier;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * <b>The playbook's definition of done, for Adjudicate</b> (#512): an adjudicator is added by
 * writing one class, and nothing else changes.
 *
 * <p>Adding one used to mean a service <em>and</em> a listener — a copy of the AFTER_COMMIT /
 * REQUIRES_NEW / try-catch plumbing that has nothing to do with adjudicating anything. That is
 * written once in the runner now.
 *
 * <p>This stage carries a rule the others do not: <b>exclusivity</b>. Scanners pile up happily; two
 * adjudicators answering one question is a bug, because the answer would depend on bean order. So
 * these tests check discovery <em>and</em> that a second claimant is refused.
 */
class AdjudicatorRegistryTest {

  /** An adjudicator that exists to prove discovery works. One class; nothing registers it. */
  static class ProbeAdjudicator implements Adjudicator {
    final List<UUID> answered = new ArrayList<>();

    @Override
    public String question() {
      return "probe-question";
    }

    @Override
    public Tier tier() {
      return Tier.DETERMINISTIC;
    }

    @Override
    public void adjudicate(UUID fileId) {
      answered.add(fileId);
    }
  }

  /** The one that matters: a class nobody registered is asked its question when facts land. */
  @Test
  void anAdjudicatorDeclaredNowhereButItsOwnFileIsAskedWhenFactsChange() {
    ProbeAdjudicator probe = new ProbeAdjudicator();
    AdjudicatorRunner runner = new AdjudicatorRunner(List.of(probe));
    UUID fileId = UUID.randomUUID();

    runner.onAnalysisCompleted(new AnalysisCompletedEvent(fileId));

    assertThat(probe.answered).containsExactly(fileId);
  }

  /**
   * The rule that makes this stage different, made structural: two modules claiming one question
   * cannot start. Picking a winner by bean order would make the answer change with an unrelated
   * refactor — the worst failure available to a stage whose job is speaking with one voice.
   */
  @Test
  void twoAdjudicatorsClaimingOneQuestionRefuseToStart() {
    AdjudicatorRunner runner =
        new AdjudicatorRunner(List.of(new ProbeAdjudicator(), new ProbeAdjudicator()));

    assertThatThrownBy(runner::validate)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Adjudicate is exclusive")
        .hasMessageContaining("probe-question");
  }

  /** Distinct questions are fine — the constraint is one voice per question, not one adjudicator. */
  @Test
  void adjudicatorsAnsweringDifferentQuestionsCoexist() {
    Adjudicator other =
        new ProbeAdjudicator() {
          @Override
          public String question() {
            return "some-other-question";
          }
        };
    AdjudicatorRunner runner = new AdjudicatorRunner(List.of(new ProbeAdjudicator(), other));

    runner.validate(); // must not throw

    assertThat(runner.registeredQuestions()).containsExactly("probe-question", "some-other-question");
  }

  /** A human annotating something re-opens every question — staleness IS re-adjudication. */
  @Test
  void anAnnotationChangeReAsksTheQuestion() {
    ProbeAdjudicator probe = new ProbeAdjudicator();
    AdjudicatorRunner runner = new AdjudicatorRunner(List.of(probe));
    UUID fileId = UUID.randomUUID();

    runner.onNodeRoleChanged(new com.tracepcap.common.event.NodeRoleChangedEvent(fileId));

    assertThat(probe.answered).containsExactly(fileId);
  }

  /** One question failing must not cost the others their answers. */
  @Test
  void aThrowingAdjudicatorIsIsolated() {
    Adjudicator boom =
        new ProbeAdjudicator() {
          @Override
          public String question() {
            return "explodes";
          }

          @Override
          public void adjudicate(UUID fileId) {
            throw new IllegalStateException("no evidence");
          }
        };
    ProbeAdjudicator survivor = new ProbeAdjudicator();
    AdjudicatorRunner runner = new AdjudicatorRunner(List.of(boom, survivor));
    UUID fileId = UUID.randomUUID();

    runner.onAnalysisCompleted(new AnalysisCompletedEvent(fileId));

    assertThat(survivor.answered).as("a peer's failure must not silence this one").containsExactly(fileId);
  }
}
