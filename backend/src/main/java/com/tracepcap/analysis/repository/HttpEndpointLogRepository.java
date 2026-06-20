package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.HttpEndpointLogEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface HttpEndpointLogRepository extends JpaRepository<HttpEndpointLogEntity, UUID> {

  List<HttpEndpointLogEntity> findByFileId(UUID fileId);

  List<HttpEndpointLogEntity> findByFileIdAndServerIp(UUID fileId, String serverIp);

  void deleteByFileId(UUID fileId);
}
