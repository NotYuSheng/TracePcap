package com.tracepcap.common.adjudication.dto;

import java.time.LocalDateTime;
import java.util.List;
import lombok.Builder;
import lombok.Value;

/** A persisted human override, including its audit trail (who set it, when). */
@Value
@Builder
public class OverrideDto {
  String question;
  String entityKey;
  String label;
  String rationale;
  /** Who overrode: username, or "system" when auth is off. */
  String actor;
  LocalDateTime createdAt;
  LocalDateTime updatedAt;
  /** Set when this carried-forward override drifted in monitor mode (#499); null when current. */
  LocalDateTime staleSince;
  /** The changes that made it stale, e.g. ["MAC changed (…)"]; null/empty when current. */
  List<String> staleFields;
}
