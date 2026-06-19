package com.tracepcap.tracer.dto;

import lombok.Builder;
import lombok.Data;

/** A peer that the traced host exchanged packets with, plus whether it responded. */
@Data
@Builder
public class TracerPeer {
  private String ip;
  private String conversationId; // representative conversation between host and this peer
  private String protocol;
  private long packetCount;
  private boolean responded; // true if the peer sent at least one packet back to the host
}
