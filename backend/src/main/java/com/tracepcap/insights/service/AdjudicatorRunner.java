package com.tracepcap.insights.service;

import com.tracepcap.common.event.AnalysisCompletedEvent;
import com.tracepcap.common.event.NodeRoleChangedEvent;
import com.tracepcap.common.stage.Adjudicator;
import com.tracepcap.common.stage.Tier;
import jakarta.annotation.PostConstruct;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Runs every {@link Adjudicator} on the classpath when the facts they answer from change.
 *
 * <p><b>It names no adjudicator.</b> Adding one is adding one class (#512). Before this, an
 * adjudicator also needed its own listener — a copy of the {@code AFTER_COMMIT} +
 * {@code REQUIRES_NEW} + try/catch plumbing, which has nothing to do with adjudicating anything.
 * That plumbing is written once here.
 *
 * <p><b>It enforces exclusivity at startup.</b> Unlike scanners, two adjudicators answering one
 * question is a bug, not a feature — the answer would depend on bean order. {@link #validate}
 * refuses to start rather than let that ship.
 *
 * <p><b>Re-adjudication is the point.</b> Conclusions are revisable: this fires on analysis
 * completion (new facts) and on node-role changes (a human annotated something). Staleness is not a
 * separate mechanism — it is this one.
 */
@Slf4j
@Component
public class AdjudicatorRunner {

  private final List<Adjudicator> adjudicators;

  /**
   * Each adjudicator runs in its own transaction.
   *
   * <p>Not decoration. A single {@code @Transactional} around the loop would put every adjudicator
   * in one transaction, so a DB failure in one — a constraint violation, say — marks it
   * rollback-only, and every other adjudicator's work is discarded at commit <em>despite</em> the
   * catch below. The catch would run, the log would say "isolated", and the answers would still be
   * gone. Same trap as the REQUIRES_NEW proxy boundary in #515: catching an exception does not
   * un-poison a transaction it already marked.
   *
   * <p>A TransactionTemplate rather than a self-injected proxy: the boundary is visible at the call
   * site instead of depending on which bean reference the call happens to go through.
   */
  private final TransactionTemplate perAdjudicator;

  public AdjudicatorRunner(List<Adjudicator> adjudicators, PlatformTransactionManager txManager) {
    this.adjudicators = adjudicators;
    this.perAdjudicator = new TransactionTemplate(txManager);
    this.perAdjudicator.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
  }

  /**
   * Fails startup when two modules claim the same question.
   *
   * <p>Loud and early on purpose. The alternative — picking one by bean order — would give an
   * answer that changes with an unrelated refactor, which is the worst possible failure for a stage
   * whose entire job is speaking with one voice.
   */
  @PostConstruct
  void validate() {
    Map<String, List<String>> byQuestion =
        adjudicators.stream()
            .collect(
                Collectors.groupingBy(
                    Adjudicator::question,
                    Collectors.mapping(a -> a.getClass().getSimpleName(), Collectors.toList())));

    List<String> contested =
        byQuestion.entrySet().stream()
            .filter(e -> e.getValue().size() > 1)
            .map(e -> e.getKey() + " claimed by " + e.getValue())
            .toList();

    if (!contested.isEmpty()) {
      throw new IllegalStateException(
          "Adjudicate is exclusive: one module per question (#512). Contested: "
              + String.join("; ", contested));
    }

    log.info(
        "Adjudicate: {} adjudicator(s) ({}) — questions: {}",
        adjudicators.size(),
        tierBreakdown(),
        byQuestion.keySet().stream().sorted().collect(Collectors.joining(", ")));
  }

  /** New facts landed: every question is worth re-answering. */
  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onAnalysisCompleted(AnalysisCompletedEvent event) {
    runAll(event.fileId(), "analysis completion");
  }

  /** A human annotated something: their input ranks first, so conclusions may change. */
  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onNodeRoleChanged(NodeRoleChangedEvent event) {
    runAll(event.fileId(), "node-role change");
  }

  private void runAll(UUID fileId, String trigger) {
    for (Adjudicator adjudicator : adjudicators) {
      try {
        // Its own transaction: a rollback here cannot reach a peer's committed answer.
        perAdjudicator.executeWithoutResult(status -> adjudicator.adjudicate(fileId));
      } catch (Exception e) {
        // One question failing must not cost the others their answers. The whole exception, not
        // getMessage(): an NPE's message is null.
        log.error(
            "Adjudication of '{}' failed for file {} ({})",
            adjudicator.question(),
            fileId,
            trigger,
            e);
      }
    }
  }

  private String tierBreakdown() {
    return adjudicators.stream()
        .collect(Collectors.groupingBy(Adjudicator::tier, Collectors.counting()))
        .entrySet()
        .stream()
        .sorted(Comparator.comparing(e -> e.getKey().name()))
        .map(e -> e.getValue() + " " + e.getKey())
        .collect(Collectors.joining(", "));
  }

  /** Exposed for the adjudicate-registry test: which questions are claimed. */
  List<String> registeredQuestions() {
    return adjudicators.stream().map(Adjudicator::question).sorted().toList();
  }
}
