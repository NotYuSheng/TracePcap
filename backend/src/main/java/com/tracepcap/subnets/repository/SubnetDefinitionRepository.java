package com.tracepcap.subnets.repository;

import com.tracepcap.subnets.entity.SubnetDefinitionEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SubnetDefinitionRepository extends JpaRepository<SubnetDefinitionEntity, Long> {

  Optional<SubnetDefinitionEntity> findByCidr(String cidr);
}
