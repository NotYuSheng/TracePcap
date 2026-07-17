package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Read port for individual packets within a conversation (#512 slice 6c).
 *
 * <p>Separate from {@link ConversationLookup} rather than nested inside it, because the grain is
 * different: a conversation is a summary of many packets, and a consumer that wants one wants the
 * other only rarely. Folding packets into {@code ConversationFacts} would make every timeline bin
 * drag thousands of packet rows behind it.
 *
 * <p>All packet facts are <b>MEASURED</b> — a packet's size, its ordinal, who sent it. The one
 * exception is {@link PacketFacts#detectedFileType()}, which is a carver's inference; it is called
 * out on the field rather than split into its own group, since it is the only one.
 */
public interface PacketLookup {

  /**
   * One packet as observed on the wire.
   *
   * <p>Never null: {@code id}, {@code packetNumber}, {@code srcIp}, {@code dstIp}, {@code
   * packetSize} — all {@code NOT NULL} columns. Nullable: the ports (absent for ICMP/ARP), {@code
   * timestamp}, {@code protocol}, {@code info}, {@code payload} (only captured when payload
   * retention is on), and {@code detectedFileType} (only set when a carver matched).
   */
  record PacketFacts(
      UUID id,
      long packetNumber,
      LocalDateTime timestamp,
      String srcIp,
      Integer srcPort,
      String dstIp,
      Integer dstPort,
      String protocol,
      int packetSize,
      String info,
      String payload,
      String detectedFileType) {}

  /**
   * Every packet in a conversation, <b>ordered by packet number ascending</b> — the order they were
   * observed. The ordering is contractual: consumers render these as a sequence of steps, so an
   * arbitrary order would silently rewrite the story the packets tell.
   */
  List<PacketFacts> packetsInConversation(UUID conversationId);

  /**
   * Ids of the conversations in which {@code hostIp}'s peer sent at least one packet back — i.e.
   * the peer responded rather than staying silent.
   *
   * <p>Answers the question directly instead of returning packets for the caller to sift: "did this
   * peer reply?" is what the tracer asks, and computing it here keeps the packet rows out of the
   * caller entirely.
   */
  List<UUID> conversationIdsWithReplyFromPeer(UUID fileId, String hostIp);

  /**
   * Of the given conversations, those carrying at least one packet whose payload a carver
   * recognised as a file — the set worth reassembling streams for.
   *
   * <p>Ids only, not the file types: the caller is choosing which conversations to scan, and the
   * types it would find are rediscovered during the scan itself. An empty or null input yields an
   * empty set.
   */
  Set<UUID> conversationIdsWithDetectedFiles(Collection<UUID> conversationIds);

  /**
   * The conversation containing a given frame number in a file, so a UI can open and highlight it.
   *
   * <p>Empty when no such frame exists, or when the frame belongs to no conversation (a stray packet
   * that never got associated). Returns the id alone — the caller is navigating, and asking for the
   * whole conversation to read one field would be a wasted load.
   */
  Optional<UUID> conversationIdForFrame(UUID fileId, long packetNumber);
}
