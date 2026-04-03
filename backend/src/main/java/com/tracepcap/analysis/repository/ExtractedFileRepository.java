package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.ExtractedFileEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ExtractedFileRepository extends JpaRepository<ExtractedFileEntity, UUID> {

  List<ExtractedFileEntity> findByFileIdOrderByCreatedAtAsc(UUID fileId);

  List<ExtractedFileEntity> findByConversationId(UUID conversationId);

  long countByConversationId(UUID conversationId);

  boolean existsByFileIdAndSha256(UUID fileId, String sha256);
}
