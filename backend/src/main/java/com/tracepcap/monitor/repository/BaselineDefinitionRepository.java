package com.lanturn.monitor.repository;

import com.lanturn.monitor.entity.BaselineDefinitionEntity;
import com.lanturn.monitor.entity.BaselineDefinitionEntity.BaselineEntryType;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BaselineDefinitionRepository
    extends JpaRepository<BaselineDefinitionEntity, UUID> {

  List<BaselineDefinitionEntity> findByNetworkIdOrderByCreatedAtAsc(UUID networkId);

  List<BaselineDefinitionEntity> findByNetworkIdAndEntryType(
      UUID networkId, BaselineEntryType entryType);

  void deleteByNetworkId(UUID networkId);
}
