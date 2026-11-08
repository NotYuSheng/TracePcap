package com.tracepcap.subnets.repository;

import com.tracepcap.subnets.entity.SubnetDefinitionEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SubnetDefinitionRepository extends JpaRepository<SubnetDefinitionEntity, Long> {

  /** The shared default's subnet for a CIDR (#915 phase 4). */
  Optional<SubnetDefinitionEntity> findByCidrAndNetworkIdIsNull(String cidr);

  /** The shared default, by CIDR. */
  java.util.List<SubnetDefinitionEntity> findByNetworkIdIsNullOrderByCidr();

  /** One network's own entries, hidden ones included. */
  java.util.List<SubnetDefinitionEntity> findByNetworkIdOrderByCidr(java.util.UUID networkId);

  Optional<SubnetDefinitionEntity> findByNetworkIdAndCidr(java.util.UUID networkId, String cidr);
}
