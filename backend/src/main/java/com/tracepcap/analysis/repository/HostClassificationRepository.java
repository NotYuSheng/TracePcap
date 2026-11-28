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

  /** The first page of a file's rows in id order: {@code InPages}. */
  List<HostClassificationEntity> findByFileIdOrderByIdAsc(UUID fileId, org.springframework.data.domain.Limit limit);

  /** The page after {@code after}: {@code InPages}. */
  List<HostClassificationEntity> findByFileIdAndIdGreaterThanOrderByIdAsc(
      UUID fileId, UUID after, org.springframework.data.domain.Limit limit);

  /** The addresses of one kind (a failover address, say), without loading the hosts. */
  @org.springframework.data.jpa.repository.Query(
      "SELECT h.ip FROM HostClassificationEntity h WHERE h.file.id = :fileId AND h.addressKind = :kind")
  java.util.Set<String> findIpsByAddressKind(
      @org.springframework.data.repository.query.Param("fileId") UUID fileId,
      @org.springframework.data.repository.query.Param("kind") String kind);

  List<HostClassificationEntity> findByFileIdAndIpIn(UUID fileId, java.util.Collection<String> ips);

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
