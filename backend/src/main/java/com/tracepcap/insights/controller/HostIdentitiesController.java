package com.tracepcap.insights.controller;

import com.tracepcap.insights.dto.HostIdentityDto;
import com.tracepcap.insights.repository.HostIdentityRepository;
import com.tracepcap.insights.service.HostIdentityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Read surface for adjudicated host identities (#512 slice 5, #499/#498). */
@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(name = "Host Identities", description = "Adjudicated per-file host identities — one answer per host, or an explicit contest")
public class HostIdentitiesController {

  private final HostIdentityRepository hostIdentityRepository;
  private final HostIdentityService hostIdentityService;

  @GetMapping("/{fileId}/host-identities")
  @Operation(summary = "Adjudicated identity per host for a file (winner-or-contested)")
  public ResponseEntity<List<HostIdentityDto>> getHostIdentities(@PathVariable UUID fileId) {
    // Lazy backfill (#521): files analysed before the adjudicator existed have classifications but
    // no identities, so the frontend — which now renders the adjudicated label and nothing else —
    // would show every node as "unknown". Adjudicate on first read instead. Idempotent: it reads
    // the same classifications and produces the same winners, so a file with fresh identities is
    // untouched, and the cost is paid once per legacy file.
    if (hostIdentityRepository.findByFileId(fileId).isEmpty()) {
      hostIdentityService.adjudicateFile(fileId);
    }

    List<HostIdentityDto> result =
        hostIdentityRepository.findByFileId(fileId).stream()
            .map(
                e ->
                    HostIdentityDto.builder()
                        .ip(e.getIp())
                        .primaryLabel(e.getPrimaryLabel())
                        .basis(e.getBasis())
                        .confidence(e.getConfidence())
                        .contested(e.isContested())
                        .candidates(e.getCandidates())
                        .build())
            .toList();
    return ResponseEntity.ok(result);
  }
}
