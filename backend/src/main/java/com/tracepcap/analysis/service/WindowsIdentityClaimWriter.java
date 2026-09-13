package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.WindowsIdentityClaimEntity;
import com.tracepcap.analysis.repository.WindowsIdentityClaimRepository;
import com.tracepcap.analysis.service.WindowsIdentityResolverService.Claim;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists a file's Windows-identity claims (#809). REQUIRES_NEW isolates the write from the
 * analysis transaction; failures propagate out of this proxy (rolling back only the inner tx) and
 * are caught by the caller — same reasoning as {@link HostnameClaimWriter}.
 */
@Service
@RequiredArgsConstructor
public class WindowsIdentityClaimWriter {

  private final WindowsIdentityClaimRepository repository;

  /** Regenerates this file's claims (re-analysis re-derives the same observations). */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void replaceForFile(UUID fileId, List<Claim> claims) {
    repository.deleteByFileId(fileId);
    if (claims.isEmpty()) return;
    repository.saveAll(
        claims.stream()
            .map(
                c ->
                    WindowsIdentityClaimEntity.builder()
                        .fileId(fileId)
                        .ip(c.ip())
                        .username(c.username())
                        .source(c.source())
                        .build())
            .toList());
  }
}
