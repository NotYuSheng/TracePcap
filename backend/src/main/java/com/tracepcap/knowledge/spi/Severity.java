package com.tracepcap.knowledge.spi;

/** How much a finding should worry an analyst. Ordered least → most severe. */
public enum Severity {
  INFO,
  LOW,
  MEDIUM,
  HIGH,
  CRITICAL
}
