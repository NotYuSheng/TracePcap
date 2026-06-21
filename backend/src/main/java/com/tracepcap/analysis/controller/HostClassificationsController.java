package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.HostClassificationResponse;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(name = "Host Classifications", description = "Per-file device-type classifications for hosts")
public class HostClassificationsController {

  private final HostClassificationRepository hostClassificationRepository;

  /** Returns the device-type classification for every unique host in the given PCAP file. */
  @GetMapping("/{fileId}/host-classifications")
  @Operation(summary = "List device-type classifications for all hosts in a file")
  public ResponseEntity<List<HostClassificationResponse>> getHostClassifications(
      @PathVariable UUID fileId) {
    List<HostClassificationEntity> entities = hostClassificationRepository.findByFileId(fileId);
    List<HostClassificationResponse> response =
        entities.stream()
            .map(
                e ->
                    HostClassificationResponse.builder()
                        .ip(e.getIp())
                        .mac(e.getMac())
                        .manufacturer(e.getManufacturer())
                        .hostname(e.getHostname())
                        .hostnameSource(e.getHostnameSource())
                        .ttl(e.getTtl())
                        .deviceType(e.getDeviceType())
                        .confidence(e.getConfidence())
                        .serviceRoles(splitRoles(e.getServiceRoles()))
                        .build())
            .toList();
    return ResponseEntity.ok(response);
  }

  /** Splits the comma-joined service_roles column into a list (empty when null/blank). */
  private static List<String> splitRoles(String joined) {
    if (joined == null || joined.isBlank()) return List.of();
    return Arrays.stream(joined.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
  }
}
