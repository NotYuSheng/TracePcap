package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.DhcpLeaseEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DhcpLeaseRepository extends JpaRepository<DhcpLeaseEntity, Long> {

  List<DhcpLeaseEntity> findByFileId(UUID fileId);

  List<DhcpLeaseEntity> findByFileIdAndIp(UUID fileId, String ip);
}
