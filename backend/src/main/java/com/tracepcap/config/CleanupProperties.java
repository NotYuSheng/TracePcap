package com.tracepcap.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Configuration properties for file cleanup */
@Configuration
@ConfigurationProperties(prefix = "tracepcap.cleanup")
@Data
public class CleanupProperties {

  /** Cron expression for cleanup schedule (default: every hour) */
  private String cron = "0 0 * * * ?";

  /** Whether cleanup is enabled */
  private boolean enabled = true;

  /** Number of hours after which files are deleted */
  private int retentionHours = 12;
}
