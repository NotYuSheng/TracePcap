package com.lanturn.tracer.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TracerStep {
  private int stepIndex;
  private long packetNumber;
  private String timestamp;
  private String direction; // "CLIENT" or "SERVER"
  private String protocol;
  private int size;
  private String info;
  private String payloadHex;
}
