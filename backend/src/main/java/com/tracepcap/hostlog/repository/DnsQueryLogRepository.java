package com.tracepcap.hostlog.repository;

import com.tracepcap.hostlog.entity.DnsQueryLogEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DnsQueryLogRepository extends JpaRepository<DnsQueryLogEntity, UUID> {

  List<DnsQueryLogEntity> findByFileId(UUID fileId);

  List<DnsQueryLogEntity> findByFileIdAndServerIp(UUID fileId, String serverIp);

  void deleteByFileId(UUID fileId);
}
