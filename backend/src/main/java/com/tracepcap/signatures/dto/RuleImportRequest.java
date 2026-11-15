package com.tracepcap.signatures.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/** A rules file to import (#925): the YAML export format, or an old signatures.yml. */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RuleImportRequest {

  public enum Mode {
    /** Add new rules and update rules with the same name; leave the rest. */
    MERGE,
    /** As MERGE, then delete global rules the file doesn't contain. */
    REPLACE
  }

  @NotNull
  @Size(max = 2_000_000)
  private String content;

  @NotNull private Mode mode = Mode.MERGE;
}
