package com.tracepcap.analysis.dto;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PacketResponse {
  private UUID id;
  private Long packetNumber;
  private LocalDateTime timestamp;
  private String srcIp;
  private Integer srcPort;
  private String dstIp;
  private Integer dstPort;
  private String protocol;
  private Integer packetSize;
  private String info;
}
