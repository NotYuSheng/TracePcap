package com.tracepcap.hostclassification.controller;

import org.springframework.web.bind.annotation.RequestParam;
import io.swagger.v3.oas.annotations.Parameter;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.IpMacObservationLookup;
import com.tracepcap.analysis.spi.WindowsLogonLookup;
import com.tracepcap.hostclassification.dto.WindowsLogonResponse;
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
  private final WindowsLogonLookup windowsLogonLookup;

  /**
   * Every Windows account seen on one host, oldest first (#812). A host can have several over one
   * capture (a shift change, a shared PC, a remote admin), so this is a timeline rather than one
   * answer. Empty when none were seen.
   */
  @GetMapping("/{fileId}/hosts/{ip}/windows-logons")
  @Operation(summary = "Windows accounts seen on a host, with when (login timeline)")
  public ResponseEntity<List<WindowsLogonResponse>> getWindowsLogons(
      @PathVariable UUID fileId, @PathVariable String ip) {
    return ResponseEntity.ok(
        windowsLogonLookup.logonsFor(fileId, ip).stream()
            .map(
                l ->
                    WindowsLogonResponse.builder()
                        .username(l.username())
                        .evidence(l.evidence())
                        .directoryEntry(l.directoryEntry())
                        .folder(l.folder())
                        .folderKind(l.folderKind())
                        .domain(l.domain())
                        .firstSeen(l.firstSeen())
                        .lastSeen(l.lastSeen())
                        .seenCount(l.seenCount())
                        .candidateOnly(l.candidateOnly())
                        .build())
            .toList());
  }

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
                        .loggedInUser(h.loggedInUser())
                        .loggedInUserSource(h.loggedInUserSource())
                        .loggedInUserCount(h.loggedInUserCount())
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
  @Operation(
      summary = "List distinct source MACs observed per IP in a file",
      description =
          "Every IP in the file by default. ip= narrows to that IP (the MACs that claimed it);"
              + " mac= narrows to the IPs that MAC claimed, each with all its MACs. If both are"
              + " given, ip wins.")
  public ResponseEntity<List<IpMacObservationsResponse>> getIpMacObservations(
      @PathVariable UUID fileId,
      @Parameter(description = "Only this IP") @RequestParam(required = false) String ip,
      @Parameter(description = "Only the IPs this MAC claimed (case-insensitive)")
          @RequestParam(required = false)
          String mac) {
    var observations =
        ip != null && !ip.isBlank()
            ? ipMacObservationLookup.ipMacObservationsForIp(fileId, ip.trim())
            : mac != null && !mac.isBlank()
                ? ipMacObservationLookup.ipMacObservationsForMac(fileId, mac.trim())
                : ipMacObservationLookup.ipMacObservations(fileId);
    List<IpMacObservationsResponse> response =
        observations.stream()
            .map(o -> IpMacObservationsResponse.builder().ip(o.ip()).macs(o.macs()).build())
            .toList();
    return ResponseEntity.ok(response);
  }
}
