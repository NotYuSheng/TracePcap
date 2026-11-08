package com.tracepcap.monitor.service;

import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.monitor.dto.NetworkDto;
import com.tracepcap.monitor.dto.CreateNetworkRequest;
import com.tracepcap.monitor.dto.UpdateNetworkRequest;
import com.tracepcap.monitor.entity.NetworkEntity;
import com.tracepcap.monitor.spi.InsightPresence;
import com.tracepcap.monitor.repository.NetworkChangeEventRepository;
import com.tracepcap.monitor.repository.NetworkRepository;
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
public class NetworkService {

  private final NetworkRepository networkRepository;
  private final NetworkSnapshotRepository snapshotRepository;
  private final NetworkChangeEventRepository changeEventRepository;
  private final InsightPresence insightPresence;

  @Transactional(readOnly = true)
  public List<NetworkDto> getAllNetworks() {
    return toDtos(networkRepository.findAllByOrderByCreatedAtDesc());
  }

  @Transactional(readOnly = true)
  public NetworkDto getNetwork(UUID networkId) {
    return toDto(findOrThrow(networkId));
  }

  public NetworkDto createNetwork(CreateNetworkRequest request) {
    NetworkEntity entity =
        NetworkEntity.builder()
            .name(request.getName().trim())
            .description(request.getDescription())
            .build();
    return toDto(networkRepository.save(entity));
  }

  public NetworkDto updateNetwork(UUID networkId, UpdateNetworkRequest request) {
    NetworkEntity entity = findOrThrow(networkId);
    if (request.getName() != null) {
      entity.setName(request.getName().trim());
    }
    if (request.getDescription() != null) {
      entity.setDescription(request.getDescription().trim().isEmpty() ? null : request.getDescription().trim());
    }
    return toDto(networkRepository.save(entity));
  }

  public void deleteNetwork(UUID networkId) {
    if (!networkRepository.existsById(networkId)) {
      throw new ResourceNotFoundException("Network not found: " + networkId);
    }
    networkRepository.deleteById(networkId);
  }

  NetworkEntity findOrThrow(UUID networkId) {
    return networkRepository
        .findById(networkId)
        .orElseThrow(() -> new ResourceNotFoundException("Network not found: " + networkId));
  }

  private NetworkDto toDto(NetworkEntity e) {
    return toDtos(List.of(e)).get(0);
  }

  /**
   * Maps networks to DTOs with a fixed four queries for the whole list (#469): snapshot counts,
   * unreviewed critical/warning counts, and insight presence, each grouped by network. It used to
   * be four queries per network on every load of the networks page. Single-network callers go
   * through here too, so there is one mapping, not two that can drift apart.
   */
  private List<NetworkDto> toDtos(List<NetworkEntity> networks) {
    if (networks.isEmpty()) return List.of();
    List<UUID> ids = networks.stream().map(NetworkEntity::getId).toList();

    Map<UUID, Long> snapshotCounts = new HashMap<>();
    for (Object[] row : snapshotRepository.countRawByNetworkIds(ids)) {
      snapshotCounts.put((UUID) row[0], ((Number) row[1]).longValue());
    }
    Map<UUID, Long> critical = new HashMap<>();
    Map<UUID, Long> warning = new HashMap<>();
    for (Object[] row : changeEventRepository.countUnreviewedBySeverityRaw(ids)) {
      Map<UUID, Long> target = "CRITICAL".equals(String.valueOf(row[1])) ? critical : warning;
      target.put((UUID) row[0], ((Number) row[2]).longValue());
    }
    Set<UUID> withInsights = insightPresence.networksWithInsights(ids);

    return networks.stream()
        .map(
            e ->
                NetworkDto.builder()
                    .id(e.getId())
                    .name(e.getName())
                    .description(e.getDescription())
                    .snapshotCount(snapshotCounts.getOrDefault(e.getId(), 0L).intValue())
                    .criticalChanges(critical.getOrDefault(e.getId(), 0L))
                    .warningChanges(warning.getOrDefault(e.getId(), 0L))
                    .hasInsights(withInsights.contains(e.getId()))
                    .createdAt(e.getCreatedAt())
                    .updatedAt(e.getUpdatedAt())
                    .build())
        .collect(Collectors.toList());
  }
}
