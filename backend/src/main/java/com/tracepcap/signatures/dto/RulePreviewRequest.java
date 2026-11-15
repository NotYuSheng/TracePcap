package com.tracepcap.signatures.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Try a rule against one capture without saving it (#925 phase 4). */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RulePreviewRequest {
  @NotNull @Valid private DetectionRuleRequest rule;
  @NotNull private UUID fileId;
}
