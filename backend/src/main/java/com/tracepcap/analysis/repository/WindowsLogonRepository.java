package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.WindowsLogonEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface WindowsLogonRepository extends JpaRepository<WindowsLogonEntity, Long> {

  /** One host's logins, oldest first: the order the timeline reads in. */
  List<WindowsLogonEntity> findByFileIdAndIpOrderByFirstSeenAscIdAsc(UUID fileId, String ip);

  @Modifying
  @Query("DELETE FROM WindowsLogonEntity w WHERE w.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
