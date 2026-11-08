package com.tracepcap.insights.repository;

import com.tracepcap.insights.entity.SnapshotInsightEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SnapshotInsightRepository extends JpaRepository<SnapshotInsightEntity, UUID> {

  Optional<SnapshotInsightEntity> findTopBySnapshotIdOrderByGeneratedAtDesc(UUID snapshotId);

  boolean existsBySnapshotId(UUID snapshotId);

  @org.springframework.data.jpa.repository.Query(
      "SELECT DISTINCT i.snapshot.id FROM SnapshotInsightEntity i WHERE i.snapshot.id IN :ids")
  java.util.List<UUID> findSnapshotIdsWithInsights(
      @org.springframework.data.repository.query.Param("ids") java.util.Collection<UUID> ids);
}
