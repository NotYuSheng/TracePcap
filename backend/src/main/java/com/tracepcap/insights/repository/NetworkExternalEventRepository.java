package com.lanturn.insights.repository;

import com.lanturn.insights.entity.NetworkExternalEventEntity;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NetworkExternalEventRepository
    extends JpaRepository<NetworkExternalEventEntity, UUID> {

  List<NetworkExternalEventEntity> findByNetworkIdOrderByEventTimeDesc(UUID networkId);

  List<NetworkExternalEventEntity> findByNetworkIdAndEventTimeBetweenOrderByEventTimeAsc(
      UUID networkId, LocalDateTime from, LocalDateTime to);
}
