package com.tracepcap.common.adjudication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * A human's override of an adjudicated question. Note there is no {@code actor} field: who overrode
 * is resolved server-side from the token, never accepted from the client.
 */
@Data
public class OverrideRequest {

  /** The human's answer — replaces the machine's conclusion. */
  @NotBlank
  @Size(max = 100)
  private String label;

  /** Why they overrode (optional). */
  @Size(max = 10_000)
  private String rationale;
}
