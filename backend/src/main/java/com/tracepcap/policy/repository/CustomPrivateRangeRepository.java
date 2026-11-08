package com.tracepcap.policy.repository;

import com.tracepcap.policy.entity.CustomPrivateRangeEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomPrivateRangeRepository extends JpaRepository<CustomPrivateRangeEntity, Long> {
  /** The shared default (#915 phase 4), newest first. */
  List<CustomPrivateRangeEntity> findByNetworkIdIsNullOrderByCreatedAtDesc();

  /** One network's own entries, hidden ones included, newest first. */
  List<CustomPrivateRangeEntity> findByNetworkIdOrderByCreatedAtDesc(java.util.UUID networkId);

  java.util.Optional<CustomPrivateRangeEntity> findByNetworkIdAndCidr(java.util.UUID networkId, String cidr);
}
