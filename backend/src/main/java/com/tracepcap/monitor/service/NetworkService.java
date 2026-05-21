package com.lanturn.monitor.service;

import com.lanturn.common.exception.ResourceNotFoundException;
import com.lanturn.monitor.dto.NetworkDto;
import com.lanturn.monitor.dto.CreateNetworkRequest;
import com.lanturn.monitor.entity.NetworkEntity;
import com.lanturn.insights.repository.NetworkInsightRepository;
import com.lanturn.monitor.repository.NetworkChangeEventRepository;
import com.lanturn.monitor.repository.NetworkRepository;
import com.lanturn.monitor.repository.NetworkSnapshotRepository;
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
  private final NetworkInsightRepository insightRepository;

  @Transactional(readOnly = true)
  public List<NetworkDto> getAllNetworks() {
    return networkRepository.findAllByOrderByCreatedAtDesc().stream()
        .map(this::toDto)
        .collect(Collectors.toList());
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
    return NetworkDto.builder()
        .id(e.getId())
        .name(e.getName())
        .description(e.getDescription())
        .snapshotCount((int) snapshotRepository.countByNetworkId(e.getId()))
        .criticalChanges(changeEventRepository.countCriticalByNetworkId(e.getId()))
        .warningChanges(changeEventRepository.countWarningByNetworkId(e.getId()))
        .hasInsights(insightRepository.existsByNetworkId(e.getId()))
        .createdAt(e.getCreatedAt())
        .updatedAt(e.getUpdatedAt())
        .build();
  }
}
