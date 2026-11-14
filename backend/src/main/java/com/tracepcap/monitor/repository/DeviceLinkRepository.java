package com.tracepcap.monitor.repository;

import com.tracepcap.monitor.entity.DeviceLinkEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceLinkRepository extends JpaRepository<DeviceLinkEntity, Long> {

  List<DeviceLinkEntity> findByNetworkIdOrderByIdAsc(UUID networkId);

  Optional<DeviceLinkEntity> findByNetworkIdAndMacAAndMacB(UUID networkId, String macA, String macB);
}
