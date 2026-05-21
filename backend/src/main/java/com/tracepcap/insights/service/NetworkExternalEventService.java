package com.lanturn.insights.service;

import com.lanturn.common.exception.ResourceNotFoundException;
import com.lanturn.insights.dto.CreateExternalEventRequest;
import com.lanturn.insights.dto.NetworkExternalEventDto;
import com.lanturn.insights.entity.NetworkExternalEventEntity;
import com.lanturn.insights.repository.NetworkExternalEventRepository;
import com.lanturn.monitor.entity.NetworkEntity;
import com.lanturn.monitor.repository.NetworkRepository;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class NetworkExternalEventService {

  private final NetworkExternalEventRepository eventRepository;
  private final NetworkRepository networkRepository;

  public List<NetworkExternalEventDto> listEvents(UUID networkId) {
    return eventRepository.findByNetworkIdOrderByEventTimeDesc(networkId).stream()
        .map(this::toDto)
        .collect(Collectors.toList());
  }

  @Transactional
  public NetworkExternalEventDto createEvent(UUID networkId, CreateExternalEventRequest req) {
    NetworkEntity network = networkRepository.findById(networkId)
        .orElseThrow(() -> new ResourceNotFoundException("Network not found: " + networkId));
    NetworkExternalEventEntity entity = NetworkExternalEventEntity.builder()
        .network(network)
        .eventTime(req.getEventTime())
        .title(req.getTitle())
        .description(req.getDescription())
        .build();
    return toDto(eventRepository.save(entity));
  }

  @Transactional
  public void deleteEvent(UUID networkId, UUID eventId) {
    NetworkExternalEventEntity event = eventRepository.findById(eventId)
        .orElseThrow(() -> new ResourceNotFoundException("Event not found: " + eventId));
    if (!event.getNetwork().getId().equals(networkId)) {
      throw new ResourceNotFoundException("Event not found in network: " + eventId);
    }
    eventRepository.deleteById(eventId);
  }

  private NetworkExternalEventDto toDto(NetworkExternalEventEntity e) {
    return NetworkExternalEventDto.builder()
        .id(e.getId())
        .networkId(e.getNetwork().getId())
        .eventTime(e.getEventTime())
        .title(e.getTitle())
        .description(e.getDescription())
        .createdAt(e.getCreatedAt())
        .build();
  }
}
