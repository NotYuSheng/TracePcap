package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Pins where the analysis pipeline's transaction starts and ends (#409).
 *
 * <p>Two properties, each of which has been lost once:
 *
 * <ul>
 *   <li><b>Every write runs in a real transaction.</b> #750 removed {@code @Transactional} while
 *       restructuring, and nothing noticed. Small captures analysed fine, because JPA autocommits
 *       each save. The failure needs more than {@code JPA_FLUSH_INTERVAL} (50) conversations,
 *       because only then does the batch {@code EntityManager.flush()} run, and outside a
 *       transaction it throws. {@code PipelineIntegrationTest} now analyses such a capture. This
 *       test catches the copy-paste version: a read-only or suspended template.
 *   <li><b>The tool runs are outside it.</b> Until #409, the whole method was
 *       {@code @Transactional}, so Suricata, ndpiReader and tshark (about 90% of an analysis) held
 *       a pooled connection open and idle. Re-adding the annotation would compile and pass every
 *       functional test.
 * </ul>
 */
class AnalysisTransactionBoundaryTest {

  @Test
  void analyzeFileDoesNotWrapTheToolRunsInATransaction() throws Exception {
    Method analyze = AnalysisService.class.getMethod("analyzeFile", UUID.class);

    assertThat(analyze.getAnnotation(Transactional.class))
        .as(
            "analyzeFile must not be @Transactional: the download and ExtractorRunner.prepareAll"
                + " would then hold a DB connection for the length of every Suricata run (#409)."
                + " The writes have their own transaction, in pipelineTx()")
        .isNull();
    assertThat(AnalysisService.class.getAnnotation(Transactional.class))
        .as("a class-level @Transactional would re-wrap analyzeFile")
        .isNull();
  }

  @Test
  void theWritePhaseRunsInARealReadWriteTransaction() throws Exception {
    TransactionTemplate tx = serviceWithOnly(mock(PlatformTransactionManager.class)).pipelineTx();

    // readOnly is a plausible copy-paste from the read-only query methods in the same class, and
    // NOT_SUPPORTED/NEVER suspend the transaction. Both would reproduce the #750 failure exactly.
    assertThat(tx.isReadOnly()).as("a read-only transaction cannot flush writes").isFalse();
    assertThat(tx.getPropagationBehavior())
        .as("the write phase must run inside a real transaction, not with one suspended")
        .isIn(TransactionDefinition.PROPAGATION_REQUIRED, TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    assertThat(tx.getTransactionManager()).isNotNull();
  }

  /**
   * Builds the service with every collaborator null except the transaction manager. Reflection
   * rather than a 25-argument call, so adding a dependency doesn't break this test.
   */
  private static AnalysisService serviceWithOnly(PlatformTransactionManager txManager)
      throws Exception {
    Constructor<?> ctor =
        Arrays.stream(AnalysisService.class.getDeclaredConstructors())
            .max((a, b) -> Integer.compare(a.getParameterCount(), b.getParameterCount()))
            .orElseThrow();
    Object[] args = new Object[ctor.getParameterCount()];
    Class<?>[] types = ctor.getParameterTypes();
    for (int i = 0; i < types.length; i++) {
      if (types[i] == PlatformTransactionManager.class) args[i] = txManager;
    }
    ctor.setAccessible(true);
    return (AnalysisService) ctor.newInstance(args);
  }
}
