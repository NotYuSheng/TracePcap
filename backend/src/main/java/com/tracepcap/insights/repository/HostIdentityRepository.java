package com.tracepcap.insights.repository;

import com.tracepcap.insights.entity.HostIdentityEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface HostIdentityRepository extends JpaRepository<HostIdentityEntity, Long> {

  List<HostIdentityEntity> findByFileId(UUID fileId);

  /** Bulk delete — re-adjudication regenerates the file's rows. */
  @Modifying
  @Query("DELETE FROM HostIdentityEntity h WHERE h.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
