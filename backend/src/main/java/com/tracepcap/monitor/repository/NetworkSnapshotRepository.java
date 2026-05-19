package com.tracepcap.monitor.repository;

import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface NetworkSnapshotRepository extends JpaRepository<NetworkSnapshotEntity, UUID> {

  List<NetworkSnapshotEntity> findByNetworkIdOrderBySnapshotOrderAsc(UUID networkId);

  Optional<NetworkSnapshotEntity> findByNetworkIdAndIsBaselineTrue(UUID networkId);

  Optional<NetworkSnapshotEntity> findByNetworkIdAndFileId(UUID networkId, UUID fileId);

  long countByNetworkId(UUID networkId);

  void deleteByNetworkId(UUID networkId);

  @Query(
      "SELECT s FROM NetworkSnapshotEntity s"
          + " WHERE s.network.id = :networkId"
          + " ORDER BY s.file.startTime ASC NULLS LAST, s.addedAt ASC")
  List<NetworkSnapshotEntity> findOrderedByStartTime(@Param("networkId") UUID networkId);
}
