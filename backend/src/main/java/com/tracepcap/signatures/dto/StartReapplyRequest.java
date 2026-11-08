package com.tracepcap.signatures.dto;

import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/** What to re-apply the rules to (#925 phase 2). */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class StartReapplyRequest {
  /** One capture; omit for every capture that's out of date. */
  private UUID fileId;
}
