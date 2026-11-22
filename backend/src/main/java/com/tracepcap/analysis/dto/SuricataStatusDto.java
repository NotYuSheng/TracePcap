package com.tracepcap.analysis.dto;

import java.time.LocalDate;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** The Suricata engine and the ruleset it uses (#600): which one, how old, and any import problem. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SuricataStatusDto {
  /** The installed Suricata package version, e.g. "1:6.0.4-3". */
  private String engineVersion;
  /** "built-in" (baked into the image) or "imported" (from the import folder). */
  private String source;
  /** When the ruleset was published (imported) or the image was built (built-in); null if unknown. */
  private LocalDate rulesetDate;
  private Long ageDays;
  /** Older than {@link #staleAfterDays}: its signatures may miss recent threats. */
  private boolean stale;
  private int staleAfterDays;
  private int ruleCount;
  /** The folder an operator drops a newer bundle into. */
  private String importDir;
  /** Why the last bundle in the import folder wasn't used, or null. */
  private String importError;
}
