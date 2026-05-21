package com.lanturn.insights.service;

import com.lanturn.common.exception.ResourceNotFoundException;
import com.lanturn.insights.dto.CreateAnnotationRequest;
import com.lanturn.insights.dto.NetworkAnnotationDto;
import com.lanturn.insights.entity.NetworkAnnotationEntity;
import com.lanturn.insights.repository.NetworkAnnotationRepository;
import com.lanturn.monitor.entity.NetworkEntity;
import com.lanturn.monitor.entity.NetworkSnapshotEntity;
import com.lanturn.monitor.repository.NetworkRepository;
import com.lanturn.monitor.repository.NetworkSnapshotRepository;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class NetworkAnnotationService {

  private final NetworkAnnotationRepository annotationRepository;
  private final NetworkRepository networkRepository;
  private final NetworkSnapshotRepository snapshotRepository;

  public List<NetworkAnnotationDto> listAnnotations(UUID networkId) {
    return annotationRepository.findByNetworkIdOrderByCreatedAtDesc(networkId).stream()
        .map(this::toDto)
        .collect(Collectors.toList());
  }

  @Transactional
  public NetworkAnnotationDto createAnnotation(UUID networkId, CreateAnnotationRequest req) {
    if (req.getBody() == null || req.getBody().isBlank()) {
      throw new IllegalArgumentException("Annotation body must not be blank");
    }
    NetworkEntity network = networkRepository.findById(networkId)
        .orElseThrow(() -> new ResourceNotFoundException("Network not found: " + networkId));

    NetworkSnapshotEntity snapshot = null;
    if (req.getSnapshotId() != null) {
      snapshot = snapshotRepository.findById(req.getSnapshotId())
          .filter(s -> s.getNetwork().getId().equals(networkId))
          .orElseThrow(() -> new ResourceNotFoundException(
              "Snapshot not found in network: " + req.getSnapshotId()));
    }

    NetworkAnnotationEntity entity = NetworkAnnotationEntity.builder()
        .network(network)
        .snapshot(snapshot)
        .body(req.getBody().trim())
        .build();
    return toDto(annotationRepository.save(entity));
  }

  @Transactional
  public NetworkAnnotationDto updateAnnotation(UUID networkId, UUID annotationId, String body) {
    if (body == null || body.isBlank()) {
      throw new IllegalArgumentException("Annotation body must not be blank");
    }
    NetworkAnnotationEntity annotation = annotationRepository.findById(annotationId)
        .orElseThrow(() -> new ResourceNotFoundException("Annotation not found: " + annotationId));
    if (!annotation.getNetwork().getId().equals(networkId)) {
      throw new ResourceNotFoundException("Annotation not found in network: " + annotationId);
    }
    annotation.setBody(body.trim());
    return toDto(annotationRepository.save(annotation));
  }

  @Transactional
  public void deleteAnnotation(UUID networkId, UUID annotationId) {
    NetworkAnnotationEntity annotation = annotationRepository.findById(annotationId)
        .orElseThrow(() -> new ResourceNotFoundException("Annotation not found: " + annotationId));
    if (!annotation.getNetwork().getId().equals(networkId)) {
      throw new ResourceNotFoundException("Annotation not found in network: " + annotationId);
    }
    annotationRepository.deleteById(annotationId);
  }

  private NetworkAnnotationDto toDto(NetworkAnnotationEntity e) {
    return NetworkAnnotationDto.builder()
        .id(e.getId())
        .networkId(e.getNetwork().getId())
        .snapshotId(e.getSnapshot() != null ? e.getSnapshot().getId() : null)
        .body(e.getBody())
        .createdAt(e.getCreatedAt())
        .updatedAt(e.getUpdatedAt())
        .build();
  }
}
