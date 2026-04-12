package com.tracepcap.story.dto;

import java.util.List;
import java.util.Map;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Finding {
  private FindingType type;
  private Severity severity;
  private String title;

  /** 1–2 sentences of structured evidence facts — no narrative prose */
  private String summary;

  /** Key numeric metrics, e.g. {flowCount: 12, cv: 0.08} */
  private Map<String, Object> metrics;

  private List<String> affectedIps;
}
