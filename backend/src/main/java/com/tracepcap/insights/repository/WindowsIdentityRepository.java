package com.tracepcap.insights.repository;

import com.tracepcap.insights.entity.WindowsIdentityEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface WindowsIdentityRepository extends JpaRepository<WindowsIdentityEntity, Long> {

  List<WindowsIdentityEntity> findByFileId(UUID fileId);

  /** Bulk delete — re-adjudication regenerates the file's rows. */
  @Modifying
  @Query("DELETE FROM WindowsIdentityEntity w WHERE w.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
