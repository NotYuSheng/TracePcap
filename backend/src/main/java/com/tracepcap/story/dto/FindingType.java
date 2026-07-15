package com.tracepcap.story.dto;

public enum FindingType {
  NDPI_RISK,
  BEACON,
  TLS_ANOMALY,
  VOLUME,
  FAN_OUT,
  LONG_SESSION,
  UNKNOWN_APP,
  PORT_PROTOCOL_MISMATCH,
  /** An extractor didn't run or failed, so a whole fact category is missing — a tooling gap, not a traffic finding. */
  COVERAGE_GAP
}
