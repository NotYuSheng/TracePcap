package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.ServiceBannerEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ServiceBannerRepository extends JpaRepository<ServiceBannerEntity, UUID> {

  List<ServiceBannerEntity> findByFileId(UUID fileId);

  List<ServiceBannerEntity> findByFileIdAndServerIp(UUID fileId, String serverIp);

  @Modifying
  @Query("DELETE FROM ServiceBannerEntity b WHERE b.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);
}
