package com.tracepcap.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Configuration properties for PCAP analysis */
@Configuration
@ConfigurationProperties(prefix = "tracepcap.analysis")
@Data
public class AnalysisProperties {

  /** Batch size for processing packets */
  private int batchSize = 1000;

  /** Timeout in seconds for analysis operations */
  private int timeoutSeconds = 300;

  /** Maximum number of concurrent analysis operations */
  private int maxConcurrentAnalyses = 3;

  /** Maximum number of data points to return in timeline queries */
  private int maxTimelineDataPoints = 1000;

  /** Minimum timeline interval in seconds */
  private int minTimelineInterval = 1;

  /** Whether to automatically adjust interval to respect maxTimelineDataPoints */
  private boolean autoAdjustInterval = true;
}
