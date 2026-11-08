package com.tracepcap.signatures.repository;

import com.tracepcap.signatures.entity.DetectionRuleEntity;
import com.tracepcap.signatures.entity.DetectionRuleEntity.Scope;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface DetectionRuleRepository extends JpaRepository<DetectionRuleEntity, UUID> {

  List<DetectionRuleEntity> findByScopeOrderByNameAsc(Scope scope);

  List<DetectionRuleEntity> findByScopeAndEnabledTrueOrderByNameAsc(Scope scope);

  @Query("SELECT r FROM DetectionRuleEntity r WHERE r.scope = 'GLOBAL' AND LOWER(r.name) = LOWER(?1)")
  Optional<DetectionRuleEntity> findGlobalByName(String name);
}
