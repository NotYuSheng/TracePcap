package com.tracepcap.analysis.dto.replay;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One packet for the network graph's packet replay: who sent what to whom, and when. Headers only
 * (no payload), so a page of thousands stays small.
 *
 * @param number the frame number in the capture (1-based, in capture order)
 * @param timestamp when it was captured, as recorded (capture-local, like conversation times)
 * @param conversationId the conversation it belongs to, which ties it to an edge of the graph
 * @param info the dissector's one-line summary ("Standard query A www.google.com", "[SYN]"…)
 */
public record ReplayPacket(
    long number,
    LocalDateTime timestamp,
    String srcIp,
    Integer srcPort,
    String dstIp,
    Integer dstPort,
    String protocol,
    Integer size,
    UUID conversationId,
    String info) {}
