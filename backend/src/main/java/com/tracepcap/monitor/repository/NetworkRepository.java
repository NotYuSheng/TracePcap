package com.tracepcap.monitor.repository;

import com.tracepcap.monitor.entity.NetworkEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NetworkRepository extends JpaRepository<NetworkEntity, UUID> {

  List<NetworkEntity> findAllByOrderByCreatedAtDesc();
}
