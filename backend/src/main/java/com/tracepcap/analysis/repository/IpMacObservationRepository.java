package com.tracepcap.analysis.repository;

import com.tracepcap.analysis.entity.IpMacObservationEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IpMacObservationRepository extends JpaRepository<IpMacObservationEntity, Long> {

  List<IpMacObservationEntity> findByFileId(UUID fileId);
}
