package com.tracepcap.monitor.repository;

import com.tracepcap.monitor.entity.SnapshotSubnetOverrideEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface SnapshotSubnetOverrideRepository
    extends JpaRepository<SnapshotSubnetOverrideEntity, Long> {

  List<SnapshotSubnetOverrideEntity> findBySnapshotId(UUID snapshotId);

  void deleteBySnapshotId(UUID snapshotId);

  @Query("SELECT o FROM SnapshotSubnetOverrideEntity o WHERE o.snapshot.id IN :ids")
  List<SnapshotSubnetOverrideEntity> findBySnapshotIdIn(@Param("ids") List<UUID> ids);
}
