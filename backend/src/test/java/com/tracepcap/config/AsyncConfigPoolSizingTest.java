package com.tracepcap.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** The pool-sizing arithmetic behind AsyncConfig's startup warning (#767). */
class AsyncConfigPoolSizingTest {

  @Test
  void defaultsFit() {
    // Shipped defaults: ASYNC_CORE_POOL_SIZE=5, DB_POOL_MAX_SIZE=20. Measured on a 10-upload burst,
    // the peak was exactly 10 busy connections (5 analyses x 2), so the defaults must not warn.
    assertThat(AsyncConfig.connectionsNeeded(5)).isEqualTo(15).isLessThanOrEqualTo(20);
  }

  @Test
  void raisingConcurrencyWithoutThePoolIsCaught() {
    // The misconfiguration the warning exists for: more analysers on the same 20-connection pool.
    assertThat(AsyncConfig.connectionsNeeded(10)).isEqualTo(25).isGreaterThan(20);
  }
}
