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

  /** Every rule called {@code name}, in any scope. */
  @Query("SELECT r FROM DetectionRuleEntity r WHERE LOWER(r.name) = LOWER(?1)")
  List<DetectionRuleEntity> findAllByName(String name);

  List<DetectionRuleEntity> findByScopeAndFileIdOrderByNameAsc(Scope scope, UUID fileId);

  List<DetectionRuleEntity> findByScopeAndFileIdAndEnabledTrueOrderByNameAsc(Scope scope, UUID fileId);

  List<DetectionRuleEntity> findByScopeAndEnabledTrue(Scope scope);

  List<DetectionRuleEntity> findByScopeAndNetworkIdOrderByNameAsc(Scope scope, UUID networkId);

  List<DetectionRuleEntity> findByScopeAndNetworkIdAndEnabledTrueOrderByNameAsc(Scope scope, UUID networkId);

  List<DetectionRuleEntity> findByScopeAndNetworkId(Scope scope, UUID networkId);
}
