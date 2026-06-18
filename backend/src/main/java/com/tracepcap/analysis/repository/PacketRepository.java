package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.PacketEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface PacketRepository extends JpaRepository<PacketEntity, UUID> {
  List<PacketEntity> findByConversationIdOrderByPacketNumberAsc(UUID conversationId);

  @Query(
      "SELECT p.conversation.id, p.detectedFileType FROM PacketEntity p"
          + " WHERE p.conversation.id IN :ids AND p.detectedFileType IS NOT NULL")
  List<Object[]> findFileTypesByConversationIds(@Param("ids") List<UUID> ids);

  @Query(
      "SELECT p.packetNumber FROM PacketEntity p"
          + " WHERE p.conversation.id IN :ids ORDER BY p.packetNumber ASC")
  List<Long> findPacketNumbersByConversationIds(@Param("ids") List<UUID> ids);

  /**
   * Of the given conversations, returns the ids that contain at least one packet sent by a host
   * other than {@code hostIp} — i.e. the peer transmitted back, so it "responded". Used by the
   * conversation tracer to distinguish responding from silent nodes (e.g. ARP/ICMP/port scans).
   */
  @Query(
      "SELECT DISTINCT p.conversation.id FROM PacketEntity p"
          + " WHERE p.conversation.id IN :ids AND p.srcIp <> :hostIp")
  List<UUID> findConversationIdsWithReplyFromPeer(
      @Param("ids") List<UUID> ids, @Param("hostIp") String hostIp);
}
