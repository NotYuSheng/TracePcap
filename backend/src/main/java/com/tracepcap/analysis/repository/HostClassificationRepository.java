package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface HostClassificationRepository
    extends JpaRepository<HostClassificationEntity, UUID> {

  List<HostClassificationEntity> findByFileId(UUID fileId);

  java.util.Optional<HostClassificationEntity> findByFileIdAndIp(UUID fileId, String ip);

  java.util.Optional<HostClassificationEntity> findByFileIdAndMacIgnoreCase(UUID fileId, String mac);

  long countByFileId(UUID fileId);

  void deleteByFileId(UUID fileId);
}
