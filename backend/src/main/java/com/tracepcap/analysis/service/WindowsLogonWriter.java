package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.WindowsLogonEntity;
import com.tracepcap.analysis.repository.WindowsLogonRepository;
import com.tracepcap.analysis.service.WindowsIdentityResolverService.Logon;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists a file's Windows logins (#812). Same contract as {@link HostnameClaimWriter}:
 * REQUIRES_NEW so a failure rolls back only this write, and the caller catches it, since the
 * timeline is supplementary and must not fail the analysis.
 */
@Service
@RequiredArgsConstructor
public class WindowsLogonWriter {

  private final WindowsLogonRepository repository;

  /** Regenerates this file's logins (re-analysis re-derives the same observations). */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void replaceForFile(UUID fileId, List<Logon> logons) {
    repository.deleteByFileId(fileId);
    if (logons.isEmpty()) return;
    repository.saveAll(
        logons.stream()
            .map(
                l ->
                    WindowsLogonEntity.builder()
                        .fileId(fileId)
                        .ip(l.ip())
                        .username(l.username())
                        .source(l.source())
                        .directoryEntry(l.directoryEntry())
                        .folder(l.folder())
                        .folderKind(l.folderKind() == null ? null : l.folderKind().name())
                        .domain(l.domain())
                        .firstSeen(l.firstSeen())
                        .lastSeen(l.lastSeen())
                        .seenCount(l.seenCount())
                        .build())
            .toList());
  }
}
