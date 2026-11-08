package com.tracepcap.signatures.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** A detection rule as the API returns it (#925). */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DetectionRuleDto {
  private UUID id;
  /** GLOBAL today; NETWORK and CAPTURE arrive in #925 phase 3. */
  private String scope;
  /** For a CAPTURE rule: its capture. */
  private UUID fileId;
  /** The rule this one was promoted from, if any. */
  private UUID promotedFrom;
  private String name;
  private String description;
  private String severity;
  private boolean enabled;
  private DetectionRuleRequest.Match match;
  private List<DetectionRuleRequest.PayloadPattern> payloadContains;
  private List<DetectionRuleRequest.RegexPattern> payloadRegex;
  private boolean matchAll;
  /** Legacy: overrides the matched hosts' device type. Read-only; #926 replaces it. */
  private String deviceType;
  private int version;
  private LocalDateTime createdAt;
  private String createdBy;
  private LocalDateTime updatedAt;
  private String updatedBy;
}
