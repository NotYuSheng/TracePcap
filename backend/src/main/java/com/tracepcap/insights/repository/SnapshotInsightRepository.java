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
}
