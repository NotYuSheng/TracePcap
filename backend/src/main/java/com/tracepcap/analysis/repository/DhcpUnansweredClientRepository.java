package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.DhcpUnansweredClientEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DhcpUnansweredClientRepository extends JpaRepository<DhcpUnansweredClientEntity, Long> {

  List<DhcpUnansweredClientEntity> findByFileId(UUID fileId);
}
