package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IdsAlertEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IdsAlertRepository extends JpaRepository<IdsAlertEntity, UUID> {

  List<IdsAlertEntity> findByConversationIdOrderByAlertTimeAsc(UUID conversationId);

  List<IdsAlertEntity> findByFileIdOrderByAlertTimeAsc(UUID fileId);

  @Modifying
  @Query("DELETE FROM IdsAlertEntity a WHERE a.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
