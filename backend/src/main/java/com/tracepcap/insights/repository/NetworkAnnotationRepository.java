package com.lanturn.insights.repository;

import com.lanturn.insights.entity.NetworkAnnotationEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NetworkAnnotationRepository
    extends JpaRepository<NetworkAnnotationEntity, UUID> {

  List<NetworkAnnotationEntity> findByNetworkIdOrderByCreatedAtDesc(UUID networkId);

  List<NetworkAnnotationEntity> findTop10ByNetworkIdOrderByCreatedAtDesc(UUID networkId);
}
