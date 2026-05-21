package com.lanturn.subnets.repository;

import com.lanturn.subnets.entity.SubnetDefinitionEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SubnetDefinitionRepository extends JpaRepository<SubnetDefinitionEntity, Long> {

  Optional<SubnetDefinitionEntity> findByCidr(String cidr);
}
