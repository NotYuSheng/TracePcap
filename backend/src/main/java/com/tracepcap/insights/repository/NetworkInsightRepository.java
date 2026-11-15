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

  @org.springframework.data.jpa.repository.Query(
      "SELECT DISTINCT i.network.id FROM NetworkInsightEntity i WHERE i.network.id IN :ids")
  java.util.List<UUID> findNetworkIdsWithInsights(
      @org.springframework.data.repository.query.Param("ids") java.util.Collection<UUID> ids);
}
