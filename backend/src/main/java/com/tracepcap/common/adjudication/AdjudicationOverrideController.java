package com.tracepcap.common.adjudication;

import com.tracepcap.common.adjudication.dto.EvidenceDto;
import com.tracepcap.common.adjudication.dto.EvidenceRequest;
import com.tracepcap.common.adjudication.dto.OverrideDto;
import com.tracepcap.common.adjudication.dto.OverrideRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * The generic human-override surface for any adjudicated question (adjudication explainability).
 *
 * <p><b>One controller, every question.</b> The {@code question} is a path variable — the
 * {@code Adjudicator.question()} key — so overriding "host-identity" and overriding a future
 * "os-family" go through the same endpoint with no new code. Setting or clearing an override re-runs
 * adjudication, so the conclusion reflects the human's answer at once.
 */
@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(
    name = "Adjudication Overrides",
    description = "A human's final answer to an adjudicated question — outranks the machine vote")
public class AdjudicationOverrideController {

  private final HumanOverrideService overrideService;
  private final ManualEvidenceService evidenceService;

  @GetMapping("/{fileId}/adjudications/{question}/{entityKey}/override")
  @Operation(summary = "The human override for a question about an entity, if one is set")
  @ApiResponses({
    @ApiResponse(responseCode = "200", description = "Override found"),
    @ApiResponse(responseCode = "204", description = "No override set for this entity")
  })
  public ResponseEntity<OverrideDto> get(
      @PathVariable UUID fileId,
      @PathVariable String question,
      @PathVariable String entityKey) {
    return overrideService
        .find(question, fileId, entityKey)
        .map(o -> ResponseEntity.ok(toDto(o)))
        .orElse(ResponseEntity.noContent().build());
  }

  @PutMapping("/{fileId}/adjudications/{question}/{entityKey}/override")
  @Operation(summary = "Set or replace the human override; re-runs adjudication (actor from token)")
  public ResponseEntity<OverrideDto> put(
      @PathVariable UUID fileId,
      @PathVariable String question,
      @PathVariable String entityKey,
      @Valid @RequestBody OverrideRequest request) {
    HumanOverrideEntity saved =
        overrideService.override(question, fileId, entityKey, request.getLabel(), request.getRationale());
    return ResponseEntity.ok(toDto(saved));
  }

  @DeleteMapping("/{fileId}/adjudications/{question}/{entityKey}/override")
  @Operation(summary = "Clear the human override, letting the machine vote decide again")
  @ApiResponses(@ApiResponse(responseCode = "204", description = "Override cleared"))
  public ResponseEntity<Void> delete(
      @PathVariable UUID fileId,
      @PathVariable String question,
      @PathVariable String entityKey) {
    overrideService.clear(question, fileId, entityKey);
    return ResponseEntity.noContent().build();
  }

  // ── Analyst-appended evidence (informs the vote; does not decide it) ──────────────────

  @GetMapping("/{fileId}/adjudications/{question}/{entityKey}/evidence")
  @Operation(summary = "Analyst evidence for a question about an entity, newest first")
  public ResponseEntity<List<EvidenceDto>> listEvidence(
      @PathVariable UUID fileId,
      @PathVariable String question,
      @PathVariable String entityKey) {
    List<EvidenceDto> out =
        evidenceService.forEntity(question, fileId, entityKey).stream().map(this::toDto).toList();
    return ResponseEntity.ok(out);
  }

  @PostMapping("/{fileId}/adjudications/{question}/{entityKey}/evidence")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(summary = "Append weighted evidence toward a candidate; re-runs adjudication")
  public EvidenceDto appendEvidence(
      @PathVariable UUID fileId,
      @PathVariable String question,
      @PathVariable String entityKey,
      @Valid @RequestBody EvidenceRequest request) {
    ManualEvidenceEntity saved =
        evidenceService.append(
            question, fileId, entityKey, request.getLabel(), request.getWeight(), request.getReason());
    return toDto(saved);
  }

  @PutMapping("/{fileId}/adjudications/{question}/{entityKey}/evidence/{evidenceId}")
  @Operation(summary = "Edit your own evidence; re-runs adjudication (author-only, else 403)")
  public EvidenceDto updateEvidence(
      @PathVariable UUID fileId,
      @PathVariable String question,
      @PathVariable String entityKey,
      @PathVariable Long evidenceId,
      @Valid @RequestBody EvidenceRequest request) {
    ManualEvidenceEntity saved =
        evidenceService.update(
            question, fileId, entityKey, evidenceId,
            request.getLabel(), request.getWeight(), request.getReason());
    return toDto(saved);
  }

  @DeleteMapping("/{fileId}/adjudications/{question}/{entityKey}/evidence/{evidenceId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Delete your own evidence; re-runs adjudication (author-only, else 403)")
  public void deleteEvidence(
      @PathVariable UUID fileId,
      @PathVariable String question,
      @PathVariable String entityKey,
      @PathVariable Long evidenceId) {
    evidenceService.delete(question, fileId, entityKey, evidenceId);
  }

  private OverrideDto toDto(HumanOverrideEntity e) {
    return OverrideDto.builder()
        .question(e.getQuestion())
        .entityKey(e.getEntityKey())
        .label(e.getLabel())
        .rationale(e.getRationale())
        .actor(e.getActor())
        .createdAt(e.getCreatedAt())
        .updatedAt(e.getUpdatedAt())
        .staleSince(e.getStaleSince())
        .staleFields(e.getStaleFields())
        .build();
  }

  private EvidenceDto toDto(ManualEvidenceEntity e) {
    return EvidenceDto.builder()
        .id(e.getId())
        .question(e.getQuestion())
        .entityKey(e.getEntityKey())
        .label(e.getLabel())
        .weight(e.getWeight())
        .reason(e.getReason())
        .actor(e.getActor())
        .createdAt(e.getCreatedAt())
        .build();
  }
}
