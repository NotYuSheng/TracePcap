package com.tracepcap.monitor.repository;

import com.tracepcap.monitor.entity.NetworkChangeEventEntity;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.ChangeType;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.Severity;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface NetworkChangeEventRepository
    extends JpaRepository<NetworkChangeEventEntity, UUID> {

  List<NetworkChangeEventEntity> findByNetworkIdOrderByDetectedAtDesc(UUID networkId);

  List<NetworkChangeEventEntity> findByToSnapshotId(UUID toSnapshotId);

  List<NetworkChangeEventEntity> findByToSnapshotIdOrderByDetectedAtDesc(UUID toSnapshotId);

  void deleteByToSnapshotId(UUID toSnapshotId);

  void deleteByNetworkId(UUID networkId);

  @Query(
      "SELECT e FROM NetworkChangeEventEntity e"
          + " WHERE e.network.id = :networkId"
          + " AND (:changeType IS NULL OR e.changeType = :changeType)"
          + " AND (:severity IS NULL OR e.severity = :severity)"
          + " ORDER BY e.detectedAt DESC")
  List<NetworkChangeEventEntity> findFiltered(
      @Param("networkId") UUID networkId,
      @Param("changeType") ChangeType changeType,
      @Param("severity") Severity severity);

  @Query(
      "SELECT COUNT(e) FROM NetworkChangeEventEntity e"
          + " WHERE e.toSnapshot.id = :snapshotId")
  long countByToSnapshotId(@Param("snapshotId") UUID snapshotId);

  @Query(
      "SELECT COUNT(e) FROM NetworkChangeEventEntity e"
          + " WHERE e.toSnapshot.id = :snapshotId"
          + " AND e.severity = 'CRITICAL'")
  long countCriticalByToSnapshotId(@Param("snapshotId") UUID snapshotId);

  @Query(
      "SELECT COUNT(e) FROM NetworkChangeEventEntity e"
          + " WHERE e.network.id = :networkId"
          + " AND e.severity = 'CRITICAL'"
          + " AND e.reviewed = false")
  long countCriticalByNetworkId(@Param("networkId") UUID networkId);

  @Query(
      "SELECT COUNT(e) FROM NetworkChangeEventEntity e"
          + " WHERE e.network.id = :networkId"
          + " AND e.severity = 'WARNING'"
          + " AND e.reviewed = false")
  long countWarningByNetworkId(@Param("networkId") UUID networkId);

  /** Bulk count of all events per snapshot — avoids N+1 when listing snapshots. */
  @Query(
      "SELECT e.toSnapshot.id, COUNT(e) FROM NetworkChangeEventEntity e"
          + " WHERE e.toSnapshot.id IN :ids"
          + " GROUP BY e.toSnapshot.id")
  List<Object[]> countRawByToSnapshotIds(@Param("ids") List<UUID> ids);

  /** Bulk count of CRITICAL events per snapshot. */
  @Query(
      "SELECT e.toSnapshot.id, COUNT(e) FROM NetworkChangeEventEntity e"
          + " WHERE e.toSnapshot.id IN :ids"
          + " AND e.severity = 'CRITICAL'"
          + " GROUP BY e.toSnapshot.id")
  List<Object[]> countCriticalRawByToSnapshotIds(@Param("ids") List<UUID> ids);

  default Map<UUID, Long> countByToSnapshotIds(List<UUID> ids) {
    Map<UUID, Long> result = new HashMap<>();
    for (Object[] row : countRawByToSnapshotIds(ids)) result.put((UUID) row[0], (Long) row[1]);
    return result;
  }

  default Map<UUID, Long> countCriticalByToSnapshotIds(List<UUID> ids) {
    Map<UUID, Long> result = new HashMap<>();
    for (Object[] row : countCriticalRawByToSnapshotIds(ids)) result.put((UUID) row[0], (Long) row[1]);
    return result;
  }
}
