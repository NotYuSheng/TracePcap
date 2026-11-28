package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.RouterAdvertEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RouterAdvertRepository extends JpaRepository<RouterAdvertEntity, Long> {

  List<RouterAdvertEntity> findByFileId(UUID fileId);
}
