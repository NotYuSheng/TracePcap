package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.ConversationEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ConversationRepository extends JpaRepository<ConversationEntity, UUID> {
  List<ConversationEntity> findByFileId(UUID fileId);

  Page<ConversationEntity> findByFileId(UUID fileId, Pageable pageable);

  void deleteByFileId(UUID fileId);

  /** Returns only conversations that have at least one risk flag. */
  @Query(
      value =
          "SELECT * FROM conversations WHERE file_id = :fileId AND flow_risks IS NOT NULL AND array_length(flow_risks, 1) > 0",
      nativeQuery = true)
  List<ConversationEntity> findByFileIdWithRisks(@Param("fileId") UUID fileId);
}
