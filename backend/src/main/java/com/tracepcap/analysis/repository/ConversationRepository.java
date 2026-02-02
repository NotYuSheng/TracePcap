package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.ConversationEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ConversationRepository extends JpaRepository<ConversationEntity, UUID> {
  List<ConversationEntity> findByFileId(UUID fileId);

  Page<ConversationEntity> findByFileId(UUID fileId, Pageable pageable);
}
