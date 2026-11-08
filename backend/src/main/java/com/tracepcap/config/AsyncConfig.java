package com.tracepcap.config;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/** Configuration for async task execution */
@Slf4j
@Configuration
@EnableAsync
public class AsyncConfig {

  @Value("${async.core-pool-size:5}")
  private int corePoolSize;

  @Value("${spring.datasource.hikari.maximum-pool-size:10}")
  private int dbPoolMaxSize;

  /** Connections each running analysis holds at once: its pipeline transaction + one REQUIRES_NEW write. */
  static final int CONNECTIONS_PER_ANALYSIS = 2;

  /** Connections left over for HTTP requests while analyses run. */
  static final int REQUEST_RESERVE = 5;

  @Value("${async.max-pool-size:10}")
  private int maxPoolSize;

  @Value("${async.queue-capacity:100}")
  private int queueCapacity;

  @Value("${async.thread-name-prefix:async-analysis-}")
  private String threadNamePrefix;

  @Bean(name = "asyncAnalysisExecutor")
  public Executor asyncAnalysisExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(corePoolSize);
    executor.setMaxPoolSize(maxPoolSize);
    executor.setQueueCapacity(queueCapacity);
    executor.setThreadNamePrefix(threadNamePrefix);
    // Back-pressure instead of dropping work: when all threads are busy AND the queue is full, run
    // the analysis on the calling (upload) thread. This throttles ingestion — uploads slow down —
    // rather than silently discarding files, which used to leave them stuck in PROCESSING forever
    // (see #451). Files that still fail to run (e.g. rejected during shutdown) are recovered by the
    // StuckFileReconciliationService, which flips them to FAILED past a timeout.
    executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
    executor.initialize();

    log.info(
        "Initialized async analysis executor: core={}, max={}, queue={}",
        corePoolSize,
        maxPoolSize,
        queueCapacity);

    int needed = connectionsNeeded(corePoolSize);
    if (dbPoolMaxSize < needed) {
      log.warn(
          "DB pool too small for analysis concurrency: DB_POOL_MAX_SIZE={} but {} concurrent analyses"
              + " (ASYNC_CORE_POOL_SIZE) hold up to {} connections, plus {} reserved for requests ="
              + " {}. Under an upload burst, API requests will wait for connections. Raise"
              + " DB_POOL_MAX_SIZE to at least {}, or lower ASYNC_CORE_POOL_SIZE (#767).",
          dbPoolMaxSize,
          corePoolSize,
          corePoolSize * CONNECTIONS_PER_ANALYSIS,
          REQUEST_RESERVE,
          needed,
          needed);
    }

    return executor;
  }

  /**
   * Pool size that steady-state analysis concurrency needs (#767). Steady state is the core size,
   * not the max: with a bounded queue, {@link ThreadPoolTaskExecutor} adds threads past the core
   * size only once the queue (default 100) is full.
   */
  static int connectionsNeeded(int analysisConcurrency) {
    return analysisConcurrency * CONNECTIONS_PER_ANALYSIS + REQUEST_RESERVE;
  }
}
