package com.tracepcap.subnets.repository;

import com.tracepcap.subnets.entity.SubnetNetworkBaselineEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SubnetNetworkBaselineRepository
    extends JpaRepository<SubnetNetworkBaselineEntity, SubnetNetworkBaselineEntity.Key> {

  List<SubnetNetworkBaselineEntity> findByNetworkId(UUID networkId);

  Optional<SubnetNetworkBaselineEntity> findBySubnetIdAndNetworkId(Long subnetId, UUID networkId);
}
