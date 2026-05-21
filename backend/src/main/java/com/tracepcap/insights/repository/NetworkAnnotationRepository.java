package com.tracepcap.insights.repository;

import com.tracepcap.insights.entity.NetworkAnnotationEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NetworkAnnotationRepository
    extends JpaRepository<NetworkAnnotationEntity, UUID> {

  List<NetworkAnnotationEntity> findByNetworkIdOrderByCreatedAtDesc(UUID networkId);
}
