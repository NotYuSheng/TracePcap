package com.tracepcap.governance;

import java.time.LocalDateTime;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SignedInUserRepository extends JpaRepository<SignedInUserEntity, String> {

  /** Newest sign-in first; {@code q} (a lower-case LIKE pattern, or null) matches username or name. */
  @Query(
      "SELECT u FROM SignedInUserEntity u WHERE :q IS NULL OR LOWER(u.username) LIKE :q"
          + " OR LOWER(COALESCE(u.displayName, '')) LIKE :q ORDER BY u.lastSeen DESC")
  Page<SignedInUserEntity> search(@Param("q") String q, Pageable pageable);

  /** When a sign-in last carried the client role {@code role}, or null if none ever has. */
  @Query(
      value = "SELECT max(last_seen) FROM signed_in_users WHERE :role = ANY (client_roles)",
      nativeQuery = true)
  LocalDateTime lastSeenWithRole(@Param("role") String role);
}
