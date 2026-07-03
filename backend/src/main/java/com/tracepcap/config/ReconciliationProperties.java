package com.tracepcap.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Configuration properties for stuck-file reconciliation */
@Configuration
@ConfigurationProperties(prefix = "tracepcap.reconciliation")
@Data
public class ReconciliationProperties {

  /** Cron expression for the reconciliation schedule (default: every 5 minutes) */
  private String cron = "0 */5 * * * ?";

  /** Whether stuck-file reconciliation is enabled */
  private boolean enabled = true;

  /**
   * Minutes a file may stay in PROCESSING before it is considered stuck and flipped to FAILED. Must
   * exceed the longest expected analysis time so healthy in-flight jobs are never killed.
   */
  private int timeoutMinutes = 30;
}
