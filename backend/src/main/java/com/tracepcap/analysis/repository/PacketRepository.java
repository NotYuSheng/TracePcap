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
}
