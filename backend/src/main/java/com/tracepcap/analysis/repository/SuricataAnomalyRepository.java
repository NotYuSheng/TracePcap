package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.SuricataAnomalyEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SuricataAnomalyRepository extends JpaRepository<SuricataAnomalyEntity, UUID> {

  List<SuricataAnomalyEntity> findByConversationIdOrderByTimeAsc(UUID conversationId);

  @Modifying
  @Query("DELETE FROM SuricataAnomalyEntity a WHERE a.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
