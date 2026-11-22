package com.tracepcap.governance;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleEntity, String> {

  /** Most access first: Admin, Lead, Analyst, Viewer, the order Settings › Roles lists them. */
  List<RoleEntity> findAllByOrderByPositionDescKeyAsc();

  Optional<RoleEntity> findFirstByDefaultRoleTrue();
}
