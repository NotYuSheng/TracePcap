package com.tracepcap.networkmap;

import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.security.CurrentActor;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.governance.AuditLogService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.governance.PermissionService;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reads and saves a capture's network map edits. Saving and resetting need NETWORK_MAP; both are audited. */
@Service
@RequiredArgsConstructor
public class NetworkMapEditsService {

  static final String AUDIT_TARGET = "network-map";

  private final NetworkMapEditsRepository repo;
  private final FileRepository files;
  private final PermissionService permissionService;
  private final AuditLogService auditLog;
  private final CurrentActor currentActor;

  @Transactional(readOnly = true)
  public NetworkMapEditsResponse get(UUID fileId) {
    requireFile(fileId);
    return repo.findById(fileId)
        .map(e -> new NetworkMapEditsResponse(e.getEdits(), e.getUpdatedAt(), e.getUpdatedBy()))
        .orElse(new NetworkMapEditsResponse(NetworkMapEdits.empty(), null, null));
  }

  @Transactional
  public NetworkMapEditsResponse save(UUID fileId, NetworkMapEdits edits) {
    permissionService.require(PermissionAction.NETWORK_MAP);
    requireFile(fileId);
    NetworkMapEdits before = repo.findById(fileId).map(NetworkMapEditsEntity::getEdits).orElse(null);
    NetworkMapEditsEntity saved =
        repo.save(
            NetworkMapEditsEntity.builder()
                .fileId(fileId)
                .edits(edits)
                .updatedAt(LocalDateTime.now())
                .updatedBy(currentActor.username())
                .build());
    auditLog.record("network-map.edit", AUDIT_TARGET, fileId.toString(), before, edits);
    return new NetworkMapEditsResponse(saved.getEdits(), saved.getUpdatedAt(), saved.getUpdatedBy());
  }

  /** Back to the automatic map: every edit dropped. */
  @Transactional
  public void reset(UUID fileId) {
    permissionService.require(PermissionAction.NETWORK_MAP);
    requireFile(fileId);
    repo.findById(fileId)
        .ifPresent(
            e -> {
              repo.delete(e);
              auditLog.record("network-map.reset", AUDIT_TARGET, fileId.toString(), e.getEdits(), null);
            });
  }

  private void requireFile(UUID fileId) {
    if (!files.existsById(fileId)) throw new ResourceNotFoundException("File not found: " + fileId);
  }
}
