package com.tracepcap.hostclassification.controller;

import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.IpMacObservationLookup;
import com.tracepcap.hostclassification.dto.HostClassificationResponse;
import com.tracepcap.hostclassification.dto.IpMacObservationsResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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

  private final HostClassificationLookup hostClassificationLookup;
  private final IpMacObservationLookup ipMacObservationLookup;

  /** Returns the device-type classification for every unique host in the given PCAP file. */
  @GetMapping("/{fileId}/host-classifications")
  @Operation(summary = "List device-type classifications for all hosts in a file")
  public ResponseEntity<List<HostClassificationResponse>> getHostClassifications(
      @PathVariable UUID fileId) {
    List<HostClassificationResponse> response =
        hostClassificationLookup.hostFacts(fileId).stream()
            .map(
                h ->
                    HostClassificationResponse.builder()
                        .ip(h.ip())
                        .mac(h.mac())
                        .manufacturer(h.manufacturer())
                        .hostname(h.hostname())
                        .hostnameSource(h.hostnameSource())
                        .ttl(h.ttl())
                        .deviceType(h.deviceType())
                        .confidence(h.confidence())
                        .serviceRoles(h.serviceRoles())
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
    List<IpMacObservationsResponse> response =
        ipMacObservationLookup.ipMacObservations(fileId).stream()
            .map(o -> IpMacObservationsResponse.builder().ip(o.ip()).macs(o.macs()).build())
            .toList();
    return ResponseEntity.ok(response);
  }
}
