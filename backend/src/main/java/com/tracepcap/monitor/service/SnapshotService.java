package com.tracepcap.monitor.service;

import com.tracepcap.common.exception.InvalidFileException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.entity.FileEntity.FileStatus;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.monitor.dto.NetworkSnapshotDto;
import com.tracepcap.monitor.entity.NetworkEntity;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.NetworkChangeEventRepository;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class SnapshotService {

  private final NetworkService networkService;
  private final NetworkSnapshotRepository snapshotRepository;
  private final FileRepository fileRepository;
  private final ChangeDetectionService changeDetectionService;
  private final NetworkChangeEventRepository changeEventRepository;

  @Transactional(readOnly = true)
  public List<NetworkSnapshotDto> listSnapshots(UUID networkId) {
    networkService.findOrThrow(networkId);
    return snapshotRepository.findByNetworkIdOrderBySnapshotOrderAsc(networkId).stream()
        .map(this::toDto)
        .collect(Collectors.toList());
  }

  public NetworkSnapshotDto addSnapshot(UUID networkId, UUID fileId) {
    NetworkEntity network = networkService.findOrThrow(networkId);

    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    if (file.getStatus() != FileStatus.COMPLETED) {
      throw new InvalidFileException(
          "File must be COMPLETED before adding to a network. Current status: " + file.getStatus());
    }

    if (snapshotRepository.findByNetworkIdAndFileId(networkId, fileId).isPresent()) {
      throw new InvalidFileException("File is already part of this network.");
    }

    boolean isFirst = snapshotRepository.countByNetworkId(networkId) == 0;

    NetworkSnapshotEntity snapshot =
        NetworkSnapshotEntity.builder()
            .network(network)
            .file(file)
            .snapshotOrder(0)
            .build();
    snapshot = snapshotRepository.save(snapshot);

    // Reorder all snapshots by capture start time
    reorderSnapshots(networkId);

    // Refresh after reorder
    snapshot = snapshotRepository.findById(snapshot.getId()).orElseThrow();

    // Run change detection vs. the immediately preceding snapshot
    if (!isFirst) {
      List<NetworkSnapshotEntity> ordered =
          snapshotRepository.findByNetworkIdOrderBySnapshotOrderAsc(networkId);
      int newOrder = snapshot.getSnapshotOrder();
      NetworkSnapshotEntity prev = newOrder > 0 ? ordered.get(newOrder - 1) : null;
      if (prev != null) {
        try {
          changeDetectionService.detectChanges(prev, snapshot);
        } catch (Exception e) {
          log.error(
              "Change detection failed for snapshot {} vs {}: {}",
              snapshot.getId(), prev.getId(), e.getMessage(), e);
        }
      }
    }

    return toDto(snapshot);
  }

  public void removeSnapshot(UUID networkId, UUID snapshotId) {
    networkService.findOrThrow(networkId);
    snapshotRepository
        .findById(snapshotId)
        .filter(s -> s.getNetwork().getId().equals(networkId))
        .orElseThrow(() -> new ResourceNotFoundException("Snapshot not found: " + snapshotId));

    snapshotRepository.deleteById(snapshotId);
    reorderSnapshots(networkId);
    rerunChangeDetectionChain(networkId);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  /**
   * Recomputes snapshot_order for all snapshots in the network, sorted by file.startTime ASC
   * (ties broken by addedAt ASC).
   */
  private void reorderSnapshots(UUID networkId) {
    List<NetworkSnapshotEntity> ordered =
        snapshotRepository.findOrderedByStartTime(networkId);
    for (int i = 0; i < ordered.size(); i++) {
      NetworkSnapshotEntity s = ordered.get(i);
      if (s.getSnapshotOrder() != i) {
        s.setSnapshotOrder(i);
        snapshotRepository.save(s);
      }
    }
  }

  /**
   * Deletes all change events for the network then re-runs detection for every consecutive pair
   * from the first snapshot onward.
   */
  private void rerunChangeDetectionChain(UUID networkId) {
    changeEventRepository.deleteByNetworkId(networkId);

    List<NetworkSnapshotEntity> ordered =
        snapshotRepository.findByNetworkIdOrderBySnapshotOrderAsc(networkId);
    if (ordered.size() < 2) return;

    for (int i = 1; i < ordered.size(); i++) {
      try {
        changeDetectionService.detectChanges(ordered.get(i - 1), ordered.get(i));
      } catch (Exception e) {
        log.error(
            "Change detection failed between snapshots {} and {}: {}",
            ordered.get(i - 1).getId(), ordered.get(i).getId(), e.getMessage(), e);
      }
    }
  }

  NetworkSnapshotDto toDto(NetworkSnapshotEntity s) {
    long changeCount = changeEventRepository.countByToSnapshotId(s.getId());
    long criticalCount = changeEventRepository.countCriticalByToSnapshotId(s.getId());
    return NetworkSnapshotDto.builder()
        .id(s.getId())
        .networkId(s.getNetwork().getId())
        .fileId(s.getFile().getId())
        .fileName(s.getFile().getFileName())
        .snapshotOrder(s.getSnapshotOrder())
        .startTime(s.getFile().getStartTime())
        .endTime(s.getFile().getEndTime())
        .packetCount(s.getFile().getPacketCount())
        .totalBytes(s.getFile().getTotalBytes())
        .changeCount(changeCount)
        .criticalCount(criticalCount)
        .addedAt(s.getAddedAt())
        .build();
  }
}
