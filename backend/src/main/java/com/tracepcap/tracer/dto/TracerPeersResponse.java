package com.tracepcap.tracer.dto;

import java.util.List;
import lombok.Builder;
import lombok.Data;

/**
 * Peers reached by the traced host, each flagged as responding or silent. Powers the tracer's
 * scan-style visualisation (e.g. ARP scan) where only a subset of probed targets reply.
 */
@Data
@Builder
public class TracerPeersResponse {
  private String conversationId; // the conversation that was queried
  private String hostIp; // the traced host (initiator) all peers are relative to
  private List<TracerPeer> peers;
}
