package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IdsAlertCountEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IdsAlertCountRepository extends JpaRepository<IdsAlertCountEntity, UUID> {

  List<IdsAlertCountEntity> findByFileId(UUID fileId);

  @Modifying
  @Query("DELETE FROM IdsAlertCountEntity c WHERE c.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
