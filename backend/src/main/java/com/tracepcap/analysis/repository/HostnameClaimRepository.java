package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.HostnameClaimEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface HostnameClaimRepository extends JpaRepository<HostnameClaimEntity, Long> {

  List<HostnameClaimEntity> findByFileId(UUID fileId);

  void deleteByFileId(UUID fileId);
}
