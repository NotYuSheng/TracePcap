package com.tracepcap.insights.repository;

import com.tracepcap.insights.entity.NetworkInsightEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NetworkInsightRepository extends JpaRepository<NetworkInsightEntity, UUID> {

  Optional<NetworkInsightEntity> findTopByNetworkIdOrderByGeneratedAtDesc(UUID networkId);

  boolean existsByNetworkId(UUID networkId);
}
