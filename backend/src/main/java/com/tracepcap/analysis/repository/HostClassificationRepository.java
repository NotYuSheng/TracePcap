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

  // findFirst + OrderByIdAsc (LIMIT 1, deterministic): a file can hold >1 classification for the
  // same IP or MAC (e.g. an IP claimed by two MACs during an ARP spoof), which would make a plain
  // Optional query throw NonUniqueResultException. The explicit order keeps the chosen row stable
  // so drift snapshots don't flap.
  java.util.Optional<HostClassificationEntity> findFirstByFileIdAndIpOrderByIdAsc(
      UUID fileId, String ip);

  java.util.Optional<HostClassificationEntity> findFirstByFileIdAndMacIgnoreCaseOrderByIdAsc(
      UUID fileId, String mac);

  long countByFileId(UUID fileId);

  void deleteByFileId(UUID fileId);
}
