package com.tracepcap.common.adjudication.dto;

import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Value;

/** A persisted piece of analyst evidence, including its audit trail (who added it, when). */
@Value
@Builder
public class EvidenceDto {
  Long id;
  String question;
  String entityKey;
  String label;
  int weight;
  String reason;
  /** Who added it: username, or "system" when auth is off. */
  String actor;
  LocalDateTime createdAt;
}
