package com.tracepcap.subnets.repository;

import com.tracepcap.subnets.entity.SubnetDefinitionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Subnet labels. There's no lookup by CIDR text: a row saved before #1351 may read "10.1.2.3/24"
 * for the "10.1.2.0/24" a save writes now, so the service matches by the network a CIDR names
 * ({@code Cidr.same}) over these lists.
 */
@Repository
public interface SubnetDefinitionRepository extends JpaRepository<SubnetDefinitionEntity, Long> {

  /** The shared default, by CIDR. */
  java.util.List<SubnetDefinitionEntity> findByNetworkIdIsNullOrderByCidr();

  /** One network's own entries, hidden ones included. */
  java.util.List<SubnetDefinitionEntity> findByNetworkIdOrderByCidr(java.util.UUID networkId);
}
