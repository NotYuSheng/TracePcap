package com.tracepcap.governance;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleEntity, String> {

  List<RoleEntity> findAllByOrderByPositionAscKeyAsc();

  Optional<RoleEntity> findFirstByDefaultRoleTrue();
}
