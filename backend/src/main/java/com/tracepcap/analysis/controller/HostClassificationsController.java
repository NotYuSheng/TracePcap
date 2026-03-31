package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.HostClassificationResponse;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import io.swagger.v3.oas.annotations.Operation;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
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
                        .ttl(e.getTtl())
                        .deviceType(e.getDeviceType())
                        .confidence(e.getConfidence())
                        .build())
            .toList();
    return ResponseEntity.ok(response);
  }
}
