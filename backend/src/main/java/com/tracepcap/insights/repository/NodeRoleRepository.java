package com.tracepcap.insights.repository;

import com.tracepcap.insights.entity.NodeRoleEntity;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NodeRoleRepository extends JpaRepository<NodeRoleEntity, Long> {

  Optional<NodeRoleEntity> findByEntityTypeAndEntityKey(String entityType, String entityKey);

  void deleteByEntityTypeAndEntityKey(String entityType, String entityKey);

  List<NodeRoleEntity> findByEntityTypeInAndEntityKeyIn(
      Collection<String> entityTypes, Collection<String> entityKeys);
}
