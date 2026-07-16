package com.tracepcap.insights.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.insights.dto.HostIdentityDto;
import com.tracepcap.insights.repository.HostIdentityRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.Map;
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
  private final ObjectMapper objectMapper;

  @GetMapping("/{fileId}/host-identities")
  @Operation(summary = "Adjudicated identity per host for a file (winner-or-contested)")
  public ResponseEntity<List<HostIdentityDto>> getHostIdentities(@PathVariable UUID fileId) {
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
                        .candidates(parseCandidates(e.getCandidates()))
                        .build())
            .toList();
    return ResponseEntity.ok(result);
  }

  private List<Map<String, Object>> parseCandidates(String json) {
    if (json == null) return null;
    try {
      return objectMapper.readValue(json, new TypeReference<>() {});
    } catch (Exception e) {
      return null;
    }
  }
}
