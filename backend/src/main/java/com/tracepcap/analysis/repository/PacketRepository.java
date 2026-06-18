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
   * For the given file, returns the ids of conversations involving {@code hostIp} that contain at
   * least one packet sent by the peer (a host other than {@code hostIp}) — i.e. the peer
   * transmitted back, so it "responded". Used by the conversation tracer to distinguish responding
   * from silent nodes (e.g. ARP/ICMP/port scans). Joins on file + host directly rather than passing
   * a list of ids, avoiding large IN clauses and database parameter limits.
   */
  @Query(
      "SELECT DISTINCT p.conversation.id FROM PacketEntity p"
          + " WHERE p.conversation.file.id = :fileId"
          + " AND (p.conversation.srcIp = :hostIp OR p.conversation.dstIp = :hostIp)"
          + " AND p.srcIp <> :hostIp")
  List<UUID> findConversationIdsWithReplyFromPeer(
      @Param("fileId") UUID fileId, @Param("hostIp") String hostIp);
}
