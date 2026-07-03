package com.tracepcap.insights.repository;

import com.tracepcap.insights.entity.NodeRoleEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NodeRoleRepository extends JpaRepository<NodeRoleEntity, Long> {

  Optional<NodeRoleEntity> findByFileIdAndEntityTypeAndEntityKey(
      UUID fileId, String entityType, String entityKey);

  List<NodeRoleEntity> findByFileId(UUID fileId);

  List<NodeRoleEntity> findByFileIdAndConfirmedByHumanTrue(UUID fileId);

  void deleteByFileIdAndEntityTypeAndEntityKey(UUID fileId, String entityType, String entityKey);

  void deleteByFileIdAndOrigin(UUID fileId, String origin);
}
