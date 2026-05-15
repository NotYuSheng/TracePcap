package com.tracepcap.tracer.dto;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TracerStepsResponse {
  private String conversationId;
  private String srcIp;
  private Integer srcPort;
  private String dstIp;
  private Integer dstPort;
  private String protocol;
  private String appName;
  private List<TracerStep> steps;
}
