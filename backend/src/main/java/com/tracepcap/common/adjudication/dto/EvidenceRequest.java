package com.tracepcap.common.adjudication.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * A piece of analyst-appended evidence. No {@code actor} field — who added it is resolved
 * server-side from the token, never accepted from the client.
 */
@Data
public class EvidenceRequest {

  /** Which candidate this evidence supports. */
  @NotBlank
  @Size(max = 100)
  private String label;

  /** How strongly (1–100); the service clamps to this range regardless. */
  @Min(1)
  @Max(100)
  private int weight;

  /** Why — required; evidence with no stated reason is just an unexplained nudge. */
  @NotBlank
  @Size(max = 10_000)
  private String reason;
}
