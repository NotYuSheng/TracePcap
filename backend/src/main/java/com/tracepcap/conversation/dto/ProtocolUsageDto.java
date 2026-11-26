package com.tracepcap.conversation.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** An nDPI application name and how much of your traffic it is, across the install. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProtocolUsageDto {
  /** As the analysis records it, e.g. "TLS", "SMBv23", "Outlook". */
  private String appName;
  /** Captures it appears in (originals, not re-analysis copies). */
  private long captures;
  private long conversations;
}
