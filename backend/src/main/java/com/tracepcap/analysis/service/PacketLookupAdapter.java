package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.PacketEntity;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.analysis.spi.PacketLookup;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Serves {@link PacketLookup} from the analysis module's own repository. */
@Component
@RequiredArgsConstructor
public class PacketLookupAdapter implements PacketLookup {

  private final PacketRepository repository;

  @Override
  public List<PacketFacts> packetsInConversation(UUID conversationId) {
    // The repository query carries ORDER BY packetNumber ASC, which the port promises.
    return repository.findByConversationIdOrderByPacketNumberAsc(conversationId).stream()
        .map(PacketLookupAdapter::toFacts)
        .toList();
  }

  @Override
  public List<UUID> conversationIdsWithReplyFromPeer(UUID fileId, String hostIp) {
    return repository.findConversationIdsWithReplyFromPeer(fileId, hostIp);
  }

  @Override
  public Set<UUID> conversationIdsWithDetectedFiles(Collection<UUID> conversationIds) {
    if (conversationIds == null || conversationIds.isEmpty()) return Set.of();
    // The query projects (conversationId, detectedFileType); only the id is part of the question
    // the port answers, so the type is dropped here rather than leaking an Object[] to callers.
    return repository.findFileTypesByConversationIds(List.copyOf(conversationIds)).stream()
        .map(row -> (UUID) row[0])
        .collect(Collectors.toUnmodifiableSet());
  }

  private static PacketFacts toFacts(PacketEntity p) {
    return new PacketFacts(
        p.getId(),
        p.getPacketNumber() == null ? 0L : p.getPacketNumber(),
        p.getTimestamp(),
        p.getSrcIp(),
        p.getSrcPort(),
        p.getDstIp(),
        p.getDstPort(),
        p.getProtocol(),
        p.getPacketSize() == null ? 0 : p.getPacketSize(),
        p.getInfo(),
        p.getPayload(),
        p.getDetectedFileType());
  }
}
