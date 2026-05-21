package com.lanturn.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Configuration properties for file cleanup */
@Configuration
@ConfigurationProperties(prefix = "lanturn.cleanup")
@Data
public class CleanupProperties {

  /** Cron expression for cleanup schedule (default: every hour) */
  private String cron = "0 0 * * * ?";

  /** Whether cleanup is enabled */
  private boolean enabled = true;

  /** Number of hours after which analysis files are deleted */
  private int retentionHours = 12;

  /** Number of hours after which monitor snapshot files are deleted (0 = never expire) */
  private int monitorRetentionHours = 0;
}
