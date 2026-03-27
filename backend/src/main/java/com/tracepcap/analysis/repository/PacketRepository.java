package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.PacketEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PacketRepository extends JpaRepository<PacketEntity, UUID> {
  List<PacketEntity> findByConversationIdOrderByPacketNumberAsc(UUID conversationId);

  void deleteByFileId(UUID fileId);
}
