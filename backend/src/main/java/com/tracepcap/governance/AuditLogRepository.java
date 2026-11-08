package com.tracepcap.governance;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLogEntity, Long> {

  /** Newest first. {@code q} matches actor, action, target type or target id, case-insensitively. */
  @Query(
      "SELECT a FROM AuditLogEntity a WHERE :q IS NULL"
          + " OR LOWER(a.actor) LIKE :q OR LOWER(a.action) LIKE :q"
          + " OR LOWER(a.targetType) LIKE :q OR LOWER(COALESCE(a.targetId, '')) LIKE :q"
          + " ORDER BY a.at DESC, a.id DESC")
  Page<AuditLogEntity> search(@Param("q") String q, Pageable pageable);
}
