package com.tracepcap.policy.repository;

import com.tracepcap.policy.entity.IpOrgRuleEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IpOrgRuleRepository extends JpaRepository<IpOrgRuleEntity, Long> {
  /** Returns all rules ordered by most specific prefix first, then label. */
  List<IpOrgRuleEntity> findByNetworkIdIsNullOrderByPrefixLengthDescLabelAsc();

  /** One network's own entries (#915 phase 4), hidden ones included. */
  List<IpOrgRuleEntity> findByNetworkIdOrderByPrefixLengthDescLabelAsc(java.util.UUID networkId);

  java.util.Optional<IpOrgRuleEntity> findByNetworkIdAndCidr(java.util.UUID networkId, String cidr);

  long countByNetworkIdIsNull();
}
