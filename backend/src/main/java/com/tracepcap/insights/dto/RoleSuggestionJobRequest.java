package com.tracepcap.insights.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;
import lombok.Data;

/** Which host to suggest a role for, and whether to save the suggestion or only preview it. */
@Data
public class RoleSuggestionJobRequest {
  @NotNull private UUID fileId;
  /** IP or DEVICE. */
  @NotBlank private String entityType;
  @NotBlank private String entityKey;
  /**
   * True to only suggest a label and description for the editor (a confirmed label is never
   * overwritten); false to save it as an unconfirmed AI suggestion.
   */
  private boolean preview;
}
