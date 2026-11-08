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
