package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.OccupancyDecisionEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OccupancyDecisionRepository extends JpaRepository<OccupancyDecisionEntity, Long> {

  List<OccupancyDecisionEntity> findByFileId(UUID fileId);

  List<OccupancyDecisionEntity> findByFileIdAndIpOrderByAt(UUID fileId, String ip);
}
