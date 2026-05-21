package com.lanturn.monitor.service;

import com.lanturn.common.exception.ResourceNotFoundException;
import com.lanturn.monitor.dto.BaselineDefinitionDto;
import com.lanturn.monitor.dto.CreateBaselineDefinitionRequest;
import com.lanturn.monitor.entity.BaselineDefinitionEntity;
import com.lanturn.monitor.entity.BaselineDefinitionEntity.BaselineEntryType;
import com.lanturn.monitor.entity.NetworkEntity;
import com.lanturn.monitor.repository.BaselineDefinitionRepository;
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
public class BaselineService {

  private final BaselineDefinitionRepository baselineDefinitionRepository;
  private final NetworkService networkService;

  @Transactional(readOnly = true)
  public List<BaselineDefinitionDto> listDefinitions(UUID networkId) {
    networkService.findOrThrow(networkId); // validate exists
    return baselineDefinitionRepository.findByNetworkIdOrderByCreatedAtAsc(networkId).stream()
        .map(this::toDto)
        .collect(Collectors.toList());
  }

  public BaselineDefinitionDto createDefinition(
      UUID networkId, CreateBaselineDefinitionRequest request) {
    NetworkEntity network = networkService.findOrThrow(networkId);

    BaselineEntryType entryType;
    try {
      entryType = BaselineEntryType.valueOf(request.getEntryType().toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "Invalid entry type: " + request.getEntryType()
              + ". Valid values: DEVICE, IP_MAC_BINDING, GATEWAY, PROTOCOL, APP, VPN_FINGERPRINT");
    }

    BaselineDefinitionEntity entity =
        BaselineDefinitionEntity.builder()
            .network(network)
            .entryType(entryType)
            .entityKey(request.getEntityKey().trim())
            .entityValue(request.getEntityValue())
            .notes(request.getNotes())
            .build();

    return toDto(baselineDefinitionRepository.save(entity));
  }

  public void deleteDefinition(UUID networkId, UUID definitionId) {
    networkService.findOrThrow(networkId); // validate network exists
    BaselineDefinitionEntity def =
        baselineDefinitionRepository
            .findById(definitionId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Baseline definition not found: " + definitionId));
    if (!def.getNetwork().getId().equals(networkId)) {
      throw new ResourceNotFoundException("Baseline definition not found in network: " + definitionId);
    }
    baselineDefinitionRepository.deleteById(definitionId);
  }

  private BaselineDefinitionDto toDto(BaselineDefinitionEntity e) {
    return BaselineDefinitionDto.builder()
        .id(e.getId())
        .networkId(e.getNetwork().getId())
        .entryType(e.getEntryType().name())
        .entityKey(e.getEntityKey())
        .entityValue(e.getEntityValue())
        .notes(e.getNotes())
        .createdAt(e.getCreatedAt())
        .build();
  }
}
