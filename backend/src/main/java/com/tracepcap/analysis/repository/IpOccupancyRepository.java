package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IpOccupancyEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IpOccupancyRepository extends JpaRepository<IpOccupancyEntity, Long> {

  List<IpOccupancyEntity> findByFileIdAndIpOrderByIdx(UUID fileId, String ip);

  List<IpOccupancyEntity> findByFileIdOrderByIpAscIdxAsc(UUID fileId);

  List<IpOccupancyEntity> findByFileIdAndMacIgnoreCaseOrderByIpAscIdxAsc(UUID fileId, String mac);

  @Modifying
  @Query("DELETE FROM IpOccupancyEntity o WHERE o.fileId = :fileId")
  void deleteByFileId(@Param("fileId") UUID fileId);

  @Modifying
  @Query("DELETE FROM IpOccupancyEntity o WHERE o.fileId = :fileId AND o.ip = :ip")
  void deleteByFileIdAndIp(@Param("fileId") UUID fileId, @Param("ip") String ip);
}
