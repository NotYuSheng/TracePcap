package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.HostnameClaimEntity;
import com.tracepcap.analysis.repository.HostnameClaimRepository;
import com.tracepcap.analysis.service.HostnameResolverService.Claim;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists a file's hostname claims (#512 slice 4). REQUIRES_NEW for the same reason as
 * {@code ExtractionRunService.record}: claims are best-effort observations, and a failure here
 * must not mark the analysis transaction rollback-only — a same-transaction catch would swallow
 * the exception yet still doom the outer commit.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HostnameClaimWriter {

  private final HostnameClaimRepository repository;

  /** Regenerates this file's claims (re-analysis re-derives the same observations). Never throws. */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void replaceForFile(UUID fileId, List<Claim> claims) {
    try {
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
    } catch (Exception e) {
      log.warn(
          "Failed to persist {} hostname claim(s) for file {}: {}",
          claims.size(),
          fileId,
          e.getMessage());
    }
  }
}
