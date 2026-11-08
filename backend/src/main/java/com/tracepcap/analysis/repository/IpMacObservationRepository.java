package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IpMacObservationEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IpMacObservationRepository extends JpaRepository<IpMacObservationEntity, Long> {

  List<IpMacObservationEntity> findByFileId(UUID fileId);

  /** One IP's observations in a file (#469). */
  List<IpMacObservationEntity> findByFileIdAndIpOrderById(UUID fileId, String ip);

  /** Every observation of each IP this MAC claimed in the file, matched case-insensitively (#469). */
  @Query(
      "SELECT o FROM IpMacObservationEntity o WHERE o.fileId = :fileId AND o.ip IN ("
          + "SELECT o2.ip FROM IpMacObservationEntity o2"
          + " WHERE o2.fileId = :fileId AND LOWER(o2.mac) = LOWER(:mac)) ORDER BY o.id")
  List<IpMacObservationEntity> findByFileIdForIpsClaimedByMac(
      @Param("fileId") UUID fileId, @Param("mac") String mac);
}
