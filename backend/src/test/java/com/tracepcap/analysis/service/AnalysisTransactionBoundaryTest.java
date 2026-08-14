package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@code analyzeFile} must run in a transaction.
 *
 * <p>#750 removed the annotation while restructuring the method, and nothing noticed. It compiles,
 * every unit test passes, and small captures analyse fine — JPA autocommits each save on its own.
 * The failure needs more than {@code JPA_FLUSH_INTERVAL} (50) conversations in one capture, because
 * only then does the batch flush run, and {@code EntityManager.flush()} outside a transaction
 * throws {@code TransactionRequiredException}. Every fixture used to verify that change was smaller
 * than that, so the pipeline reported success on small files and failed on real ones.
 *
 * <p>An annotation assertion is a blunt test, and the right one here: the defect was not bad logic,
 * it was a silently deleted line that no behavioural test in reach could see.
 */
class AnalysisTransactionBoundaryTest {

  @Test
  void analyzeFileIsTransactional() throws Exception {
    Method analyze = AnalysisService.class.getMethod("analyzeFile", java.util.UUID.class);

    assertThat(analyze.isAnnotationPresent(Transactional.class))
        .as(
            "analyzeFile writes conversations and packets in a batch and calls "
                + "EntityManager.flush() every %d conversations; without a transaction that throws "
                + "on any capture large enough to reach the flush",
            50)
        .isTrue();
  }
}
