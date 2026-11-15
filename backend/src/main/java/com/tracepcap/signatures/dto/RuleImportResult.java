package com.tracepcap.signatures.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** What an import did (#925). */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RuleImportResult {
  private int created;
  private int updated;
  private int unchanged;
  private int deleted;
  /** Rule names that were in the file twice; the first was used. */
  private List<String> duplicates;
}
