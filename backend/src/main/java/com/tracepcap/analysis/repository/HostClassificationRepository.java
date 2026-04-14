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

  long countByFileId(UUID fileId);

  void deleteByFileId(UUID fileId);
}
