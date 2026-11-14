package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.HostTtlWindowEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface HostTtlWindowRepository extends JpaRepository<HostTtlWindowEntity, Long> {

  List<HostTtlWindowEntity> findByFileIdAndIp(UUID fileId, String ip);
}
