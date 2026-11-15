package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.occupancy.HostOccupancyResponse;
import com.tracepcap.analysis.dto.occupancy.OccupancyDecisionRequest;
import com.tracepcap.analysis.service.HostOccupancyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

/** Which device held an address when, and the analyst's corrections (#918 item 3). */
@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(name = "Host Occupancy", description = "Devices that held one address at different times in a capture")
public class HostOccupancyController {

  private final HostOccupancyService service;

  @GetMapping("/{fileId}/occupancies")
  @Operation(
      summary = "Every address that more than one device held",
      description =
          "Each address with its devices in time order, and each device's own classification from"
              + " the traffic in its stretch. Addresses one device held throughout aren't listed.")
  public java.util.List<HostOccupancyResponse.ReusedAddress> list(@PathVariable UUID fileId) {
    return service.listForFile(fileId);
  }

  @GetMapping("/{fileId}/device-moves")
  @Operation(
      summary = "Devices that moved to another address in the capture",
      description =
          "The same MAC on one address, then another (a new DHCP lease, a re-plugged cable), with"
              + " when it left, when it arrived, its hostname on each, and each side's device key."
              + " A MAC on two addresses at once (multi-homed) isn't a move.")
  public java.util.List<com.tracepcap.analysis.dto.occupancy.DeviceMoveDto> moves(@PathVariable UUID fileId) {
    return service.moves(fileId);
  }

  @GetMapping("/{fileId}/hosts/{ip}/occupancies")
  @Operation(
      summary = "Which devices held this address, and when",
      description =
          "Occupancies come from ARP ownership claims and DHCP leases, corrected by analysts' split"
              + " and merge decisions. One occupancy means one device for the whole capture."
              + " Includes suggested split points.")
  public HostOccupancyResponse occupancies(@PathVariable UUID fileId, @PathVariable String ip) {
    return service.view(fileId, ip);
  }

  @PostMapping("/{fileId}/hosts/{ip}/occupancy-decisions")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Split the address at a time, or merge away an automatic boundary",
      description = "Needs the HOST_OCCUPANCY permission. Audited. Returns the updated occupancies.")
  public HostOccupancyResponse decide(
      @PathVariable UUID fileId, @PathVariable String ip, @Valid @RequestBody OccupancyDecisionRequest request) {
    return service.decide(fileId, ip, request);
  }

  @DeleteMapping("/{fileId}/hosts/{ip}/occupancy-decisions/{decisionId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Undo a split or merge", description = "Needs the HOST_OCCUPANCY permission. Audited.")
  public void undo(@PathVariable UUID fileId, @PathVariable String ip, @PathVariable Long decisionId) {
    service.undo(fileId, ip, decisionId);
  }
}
