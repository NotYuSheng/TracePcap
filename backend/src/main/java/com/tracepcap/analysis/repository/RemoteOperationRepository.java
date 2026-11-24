package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.RemoteOperationEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RemoteOperationRepository extends JpaRepository<RemoteOperationEntity, UUID> {

  List<RemoteOperationEntity> findByFileIdOrderByFirstTimeAsc(UUID fileId);

  @Modifying
  @Query("DELETE FROM RemoteOperationEntity o WHERE o.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
