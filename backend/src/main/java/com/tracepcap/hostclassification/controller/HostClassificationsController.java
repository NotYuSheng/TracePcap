package com.tracepcap.hostclassification.controller;

import com.tracepcap.hostclassification.dto.HostClassificationResponse;
import com.tracepcap.hostclassification.dto.IpMacObservationsResponse;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.entity.IpMacObservationEntity;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.repository.IpMacObservationRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
  private final IpMacObservationRepository ipMacObservationRepository;

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

  /**
   * All distinct MACs observed per IP in a file (#461). Most IPs have one; more than one means two
   * devices claimed the same IP in this capture (overlapping networks / ARP conflict).
   */
  @GetMapping("/{fileId}/ip-mac-observations")
  @Operation(summary = "List distinct source MACs observed per IP in a file")
  public ResponseEntity<List<IpMacObservationsResponse>> getIpMacObservations(
      @PathVariable UUID fileId) {
    Map<String, List<String>> byIp = new LinkedHashMap<>();
    for (IpMacObservationEntity o : ipMacObservationRepository.findByFileId(fileId)) {
      byIp.computeIfAbsent(o.getIp(), k -> new ArrayList<>()).add(o.getMac());
    }
    List<IpMacObservationsResponse> response =
        byIp.entrySet().stream()
            .map(e -> IpMacObservationsResponse.builder().ip(e.getKey()).macs(e.getValue()).build())
            .toList();
    return ResponseEntity.ok(response);
  }

  /** Splits the comma-joined service_roles column into a list (empty when null/blank). */
  private static List<String> splitRoles(String joined) {
    if (joined == null || joined.isBlank()) return List.of();
    return Arrays.stream(joined.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
  }
}
