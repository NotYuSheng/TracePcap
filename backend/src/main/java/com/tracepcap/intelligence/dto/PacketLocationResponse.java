package com.tracepcap.intelligence.dto;

import java.util.UUID;
import lombok.Builder;
import lombok.Value;

/**
 * Locates a packet (by frame number) so the UI can open the conversation that contains it and
 * highlight the packet.
 */
@Value
@Builder
public class PacketLocationResponse {
  UUID conversationId;
  long packetNumber;
}
