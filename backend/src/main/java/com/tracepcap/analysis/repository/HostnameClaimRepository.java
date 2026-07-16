package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.HostnameClaimEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface HostnameClaimRepository extends JpaRepository<HostnameClaimEntity, Long> {

  List<HostnameClaimEntity> findByFileId(UUID fileId);

  /** Bulk delete — the derived variant loads every row first, then deletes one by one. */
  @Modifying
  @Query("DELETE FROM HostnameClaimEntity c WHERE c.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
