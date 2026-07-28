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

  /** Number of hours after which analysis files are deleted */
  private int retentionHours = 12;

  /** Number of hours after which monitor snapshot files are deleted (0 = never expire) */
  private int monitorRetentionHours = 0;

  /**
   * Number of hours after which a file's raw packets are pruned, independently of the file itself (0
   * = prune only when the file is deleted).
   *
   * <p>Packets are the bulky part of the schema (~1.5-2M rows per GB of PCAP); conversations and
   * analysis results are compact summaries that stay useful for much longer. Setting this below
   * {@link #retentionHours} reclaims most of the storage early while leaving the analysis intact —
   * the file keeps its summaries and simply loses packet-level drill-down (#394).
   *
   * <p>Values at or above {@link #retentionHours} mean the file expires first and this never
   * triggers, which is harmless but pointless.
   */
  private int packetRetentionHours = 0;
}
