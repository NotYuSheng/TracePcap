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

  /** Snapshots referencing a given file — a file may be added to more than one network. */
  List<NetworkSnapshotEntity> findByFileId(UUID fileId);

  long countByNetworkId(UUID networkId);

  /** Snapshot count per network, for the networks list in one query (#469). */
  @Query(
      "SELECT s.network.id, COUNT(s) FROM NetworkSnapshotEntity s WHERE s.network.id IN :ids"
          + " GROUP BY s.network.id")
  List<Object[]> countRawByNetworkIds(@Param("ids") java.util.Collection<UUID> ids);

  /**
   * Networks whose snapshot_order is no longer 0..n-1 (#635). That happens when a snapshot's file is
   * deleted outside {@code SnapshotService.removeSnapshot}, for example by retention or a delete from
   * the files list. The FK cascade drops the snapshot but nothing renumbers the rest.
   */
  @Query(
      "SELECT s.network.id FROM NetworkSnapshotEntity s GROUP BY s.network.id"
          + " HAVING MIN(s.snapshotOrder) <> 0 OR MAX(s.snapshotOrder) <> COUNT(s) - 1")
  List<UUID> findNetworkIdsWithSnapshotOrderGaps();

  void deleteByNetworkId(UUID networkId);

  @Query(
      "SELECT s FROM NetworkSnapshotEntity s"
          + " WHERE s.network.id = :networkId"
          + " ORDER BY s.file.startTime ASC NULLS LAST, s.addedAt ASC")
  List<NetworkSnapshotEntity> findOrderedByStartTime(@Param("networkId") UUID networkId);

  @Query(
      "SELECT s FROM NetworkSnapshotEntity s"
          + " JOIN FETCH s.file"
          + " WHERE s.network.id = :networkId"
          + " ORDER BY s.snapshotOrder ASC")
  List<NetworkSnapshotEntity> findByNetworkIdWithFileOrderBySnapshotOrderAsc(@Param("networkId") UUID networkId);
}
