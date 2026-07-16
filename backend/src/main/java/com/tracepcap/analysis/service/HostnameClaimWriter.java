package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.HostnameClaimEntity;
import com.tracepcap.analysis.repository.HostnameClaimRepository;
import com.tracepcap.analysis.service.HostnameResolverService.Claim;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists a file's hostname claims (#512 slice 4). REQUIRES_NEW isolates the write from the
 * analysis transaction; failures propagate out of this proxy (rolling back only the inner tx) and
 * are caught by the caller. The catch must sit on the caller's side of the boundary: repository
 * methods are themselves transactional, so an in-method catch would return normally from a
 * rollback-only transaction and commit would throw UnexpectedRollbackException anyway.
 */
@Service
@RequiredArgsConstructor
public class HostnameClaimWriter {

  private final HostnameClaimRepository repository;

  /** Regenerates this file's claims (re-analysis re-derives the same observations). */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void replaceForFile(UUID fileId, List<Claim> claims) {
    repository.deleteByFileId(fileId);
    if (claims.isEmpty()) return;
    repository.saveAll(
        claims.stream()
            .map(
                c ->
                    HostnameClaimEntity.builder()
                        .fileId(fileId)
                        .ip(c.ip())
                        .hostname(c.hostname())
                        .source(c.source())
                        .build())
            .toList());
  }
}
