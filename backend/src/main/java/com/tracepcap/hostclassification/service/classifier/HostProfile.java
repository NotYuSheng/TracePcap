package com.tracepcap.hostclassification.service.classifier;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Per-host traffic profile accumulated from all conversations involving a host, used as input to the
 * device-classification signals. Not persisted.
 *
 * <p>Directional facts come from the MEASURED connection initiator (SYN without ACK, #496), never
 * from the conversation's {@code srcIp}/{@code dstIp} — those are normalised by IP sort order and do
 * not identify who opened the connection. Flows with no measured initiator (UDP/ICMP/ARP, or a
 * capture that joined mid-stream) contribute nothing directional: unknown is left unknown, never
 * backfilled from ports.
 */
public class HostProfile {
  public long totalBytes = 0;
  public long totalPackets = 0;
  public int conversationCount = 0;

  /** Flows in which this host was the MEASURED initiator (it sent SYN without ACK). */
  public int measuredInitiations = 0;

  /** Flows in which this host was the MEASURED responder (its peer opened the connection). */
  public int measuredResponses = 0;

  /** Ports this host received a connection ON, as the measured responder (its own port in the flow). */
  public final Set<Integer> respondedOnPorts = new LinkedHashSet<>();

  public final Set<String> apps = new LinkedHashSet<>();
  public final Set<String> categories = new LinkedHashSet<>();
  public final Set<String> peers = new LinkedHashSet<>();
}
