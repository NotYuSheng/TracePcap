package com.tracepcap.monitor.service;

import com.tracepcap.governance.AuditLogService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.governance.PermissionService;
import com.tracepcap.monitor.dto.NetworkSettingsDto;
import java.util.Set;
import java.util.Map;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity;
import java.time.LocalDateTime;
import java.util.ArrayList;
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
  private final PermissionService permissionService;
  private final AuditLogService auditLog;

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

  @Transactional(readOnly = true)
  public NetworkSettingsDto getSettings(UUID networkId) {
    return settingsOf(findOrThrow(networkId));
  }

  /**
   * Replaces the network's settings (#488). Validated by the controller's @Valid. Needs the
   * NETWORK_SETTINGS permission and is audited (#915).
   */
  public NetworkSettingsDto updateSettings(UUID networkId, NetworkSettingsDto settings) {
    permissionService.require(PermissionAction.NETWORK_SETTINGS);
    NetworkEntity entity = findOrThrow(networkId);
    NetworkSettingsDto before = settingsOf(entity);
    entity.setInactivityMode(settings.getInactivityMode().name());
    entity.setInactivityThreshold(settings.getInactivityThreshold());
    NetworkSettingsDto after = settingsOf(networkRepository.save(entity));
    if (!before.equals(after)) {
      auditLog.record("network.settings.update", "network", networkId.toString(), before, after);
    }
    return after;
  }

  private static NetworkSettingsDto settingsOf(NetworkEntity e) {
    NetworkSettingsDto.InactivityMode mode;
    try {
      mode = NetworkSettingsDto.InactivityMode.valueOf(e.getInactivityMode());
    } catch (IllegalArgumentException | NullPointerException ex) {
      mode = NetworkSettingsDto.DEFAULT_MODE; // the CHECK constraint makes this unreachable
    }
    return NetworkSettingsDto.builder()
        .inactivityMode(mode)
        .inactivityThreshold(
            e.getInactivityThreshold() >= 1 ? e.getInactivityThreshold() : NetworkSettingsDto.DEFAULT_THRESHOLD)
        .build();
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

    // The capture track: each capture's most severe change, two queries for the whole list.
    Map<UUID, NetworkChangeEventEntity.Severity> worst = new HashMap<>();
    for (Object[] row : changeEventRepository.severitiesBySnapshotRaw(ids)) {
      NetworkChangeEventEntity.Severity s = (NetworkChangeEventEntity.Severity) row[1];
      worst.merge((UUID) row[0], s, (a, b) -> a.ordinal() >= b.ordinal() ? a : b);
    }
    Map<UUID, List<NetworkDto.CaptureMark>> captures = new HashMap<>();
    for (Object[] row : snapshotRepository.findCaptureMarksRaw(ids)) {
      UUID networkId = (UUID) row[0];
      UUID snapshotId = (UUID) row[1];
      List<NetworkDto.CaptureMark> list = captures.computeIfAbsent(networkId, k -> new ArrayList<>());
      LocalDateTime at = row[3] != null ? (LocalDateTime) row[3] : (LocalDateTime) row[4];
      NetworkChangeEventEntity.Severity s = worst.get(snapshotId);
      list.add(
          new NetworkDto.CaptureMark(
              snapshotId, (String) row[2], at, list.isEmpty(), s == null ? "NONE" : s.name()));
    }

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
                    .captures(captures.getOrDefault(e.getId(), List.of()))
                    .settings(settingsOf(e))
                    .createdAt(e.getCreatedAt())
                    .updatedAt(e.getUpdatedAt())
                    .build())
        .collect(Collectors.toList());
  }
}
