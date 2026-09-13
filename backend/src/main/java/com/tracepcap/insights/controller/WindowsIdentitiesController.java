package com.tracepcap.insights.controller;

import com.tracepcap.analysis.spi.WindowsIdentityClaimLookup;
import com.tracepcap.common.adjudication.HumanOverrideRepository;
import com.tracepcap.insights.dto.WindowsIdentityDto;
import com.tracepcap.insights.repository.WindowsIdentityRepository;
import com.tracepcap.insights.service.WindowsIdentityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Read surface for adjudicated Windows identities (#809, closes the #808 CTF-demo gap). */
@Slf4j
@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(
    name = "Windows Identities",
    description = "Adjudicated per-file Windows identities (Kerberos/LDAP) — one answer per host with a claim, or an explicit contest")
public class WindowsIdentitiesController {

  private final WindowsIdentityRepository windowsIdentityRepository;
  private final WindowsIdentityService windowsIdentityService;
  private final WindowsIdentityClaimLookup windowsIdentityClaimLookup;
  private final HumanOverrideRepository humanOverrideRepository;

  @GetMapping("/{fileId}/windows-identities")
  @Operation(summary = "Adjudicated Windows identity per host for a file (winner-or-contested)")
  public ResponseEntity<List<WindowsIdentityDto>> getWindowsIdentities(@PathVariable UUID fileId) {
    // Lazy backfill (matches HostIdentitiesController): files analysed before this adjudicator
    // existed have claims but no adjudicated rows yet. Adjudicate on first read instead of forcing
    // every existing file through a migration/backfill job. Idempotent — safe to repeat.
    //
    // Unlike host-identity, an empty result here is a *legitimate terminal state* — most files have
    // no Kerberos/LDAP traffic at all, so "no rows yet" and "adjudicated, nothing to say" are
    // indistinguishable by row-count alone. Re-running adjudicateFile on every such GET would be
    // silent no-op work forever. Gate the backfill on there being actual signal (a claim or a human
    // override) still unreflected in the table, not merely on the table being empty.
    if (windowsIdentityRepository.findByFileId(fileId).isEmpty() && hasUnadjudicatedSignal(fileId)) {
      try {
        windowsIdentityService.adjudicateFile(fileId);
      } catch (DataIntegrityViolationException raced) {
        // Most likely a concurrent first-read of the same legacy file racing the unique (file_id,
        // ip) constraint. Fine if the rows are there now; a genuine persistence defect must not be
        // swallowed into a 200-with-nothing, so only tolerate this when they actually landed.
        if (windowsIdentityRepository.findByFileId(fileId).isEmpty()) {
          throw raced;
        }
        log.debug("Concurrent backfill for file {} lost the race; reading the winner's rows", fileId);
      }
    }

    List<WindowsIdentityDto> result =
        windowsIdentityRepository.findByFileId(fileId).stream()
            .map(
                e ->
                    WindowsIdentityDto.builder()
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

  /** True when there is a claim or a human override this file's adjudicated rows haven't seen. */
  private boolean hasUnadjudicatedSignal(UUID fileId) {
    return !windowsIdentityClaimLookup.claimsForFile(fileId).isEmpty()
        || !humanOverrideRepository
            .findByQuestionAndFileId(windowsIdentityService.question(), fileId)
            .isEmpty();
  }
}
