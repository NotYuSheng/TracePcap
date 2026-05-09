package com.tracepcap.intelligence.repository;

import com.tracepcap.intelligence.entity.IpOrgRuleEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IpOrgRuleRepository extends JpaRepository<IpOrgRuleEntity, Long> {
  /** Returns all rules ordered by most specific prefix first, then label. */
  List<IpOrgRuleEntity> findAllByOrderByPrefixLengthDescLabelAsc();
}
