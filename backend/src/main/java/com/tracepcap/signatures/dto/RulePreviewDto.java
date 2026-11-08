package com.tracepcap.signatures.dto;

import java.util.List;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** What a rule would match in one capture (#925 phase 4). */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RulePreviewDto {
  private UUID fileId;
  private String fileName;
  /** Conversations the rule would flag; null when it couldn't be checked (see packetsDeleted). */
  private Integer matches;
  /** Conversations in the capture. */
  private int conversations;
  /** The rule looks inside packets, and retention deleted this capture's packets. */
  private boolean packetsDeleted;
  /** Up to {@value com.tracepcap.signatures.service.DetectionRuleService#PREVIEW_SAMPLE} of them. */
  private List<Sample> sample;

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Sample {
    private UUID conversationId;
    private String srcIp;
    private Integer srcPort;
    private String dstIp;
    private Integer dstPort;
    private String protocol;
    private String appName;
    private String hostname;
  }
}
