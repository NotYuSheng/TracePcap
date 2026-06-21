package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.ExtractedFileResponse;
import com.tracepcap.analysis.dto.ExtractionWarningsResponse;
import com.tracepcap.analysis.entity.ExtractedFileEntity;
import com.tracepcap.analysis.repository.ExtractedFileRepository;
import com.tracepcap.analysis.service.ExtractionLimits;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.StorageService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.io.InputStream;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@Slf4j
@RestController
@RequestMapping("/files/{fileId}/extractions")
@RequiredArgsConstructor
@Tag(name = "Extracted Files", description = "Files carved from a capture, with preview and download")
public class ExtractedFilesController {

  /** Upper bound on size-skipped files returned in the warnings response. */
  private static final int MAX_SIZE_LIMIT_FILES = 100;

  private final ExtractedFileRepository extractedFileRepository;
  private final FileRepository fileRepository;
  private final StorageService storageService;
  private final ExtractionLimits extractionLimits;

  @GetMapping
  @Operation(summary = "List all files extracted from a PCAP capture")
  public ResponseEntity<List<ExtractedFileResponse>> listExtractions(
      @PathVariable UUID fileId, @RequestParam(required = false) UUID conversationId) {

    List<ExtractedFileEntity> entities =
        conversationId != null
            ? extractedFileRepository.findByConversationId(conversationId)
            : extractedFileRepository.findByFileIdOrderByCreatedAtAsc(fileId);

    List<ExtractedFileResponse> response =
        entities.stream().map(this::toResponse).collect(Collectors.toList());

    return ResponseEntity.ok(response);
  }

  @GetMapping("/warnings")
  @Operation(summary = "Report which file-extraction limits were hit for a PCAP capture")
  public ResponseEntity<ExtractionWarningsResponse> extractionWarnings(@PathVariable UUID fileId) {

    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    // Size-limit skips are persisted as extracted_files rows — query just those, capped to
    // keep the response bounded on captures with very many skipped files.
    List<ExtractionWarningsResponse.SkippedFile> sizeLimitFiles =
        extractedFileRepository
            .findByFileIdAndSkippedReasonOrderByCreatedAtAsc(fileId, "exceeds_size_limit")
            .stream()
            .limit(MAX_SIZE_LIMIT_FILES)
            .map(
                e ->
                    ExtractionWarningsResponse.SkippedFile.builder()
                        .id(e.getId())
                        .conversationId(
                            e.getConversation() != null ? e.getConversation().getId() : null)
                        .filename(e.getFilename())
                        .fileSize(e.getFileSize())
                        .build())
            .collect(Collectors.toList());

    return ResponseEntity.ok(
        ExtractionWarningsResponse.builder()
            .matchLimitConversationIds(parseConvIds(file.getExtractionMatchLimitConvIds()))
            .conversationLimitSkippedCount(file.getExtractionConversationLimitSkippedCount())
            .conversationLimitSkippedIds(
                parseConvIds(file.getExtractionConversationLimitSkippedIds()))
            .sizeLimitFiles(sizeLimitFiles)
            .maxMatchesPerStream(extractionLimits.getMaxMatchesPerStream())
            .maxStreamConversations(extractionLimits.getMaxStreamConversations())
            .maxFileSizeMb(extractionLimits.getMaxFileSizeMb())
            .build());
  }

  /**
   * Parses a comma-separated list of conversation UUIDs into a list (empty when null/blank).
   * Malformed tokens are skipped rather than failing the whole request.
   */
  private static List<UUID> parseConvIds(String csv) {
    if (csv == null || csv.isBlank()) return List.of();
    List<UUID> ids = new java.util.ArrayList<>();
    for (String token : csv.split(",")) {
      String s = token.trim();
      if (s.isEmpty()) continue;
      try {
        ids.add(UUID.fromString(s));
      } catch (IllegalArgumentException e) {
        log.warn("Skipping malformed conversation id in extraction warning: {}", s);
      }
    }
    return ids;
  }

  /** MIME types the browser can safely render inline without a plugin. */
  private static final java.util.Set<String> INLINE_SAFE_MIME_TYPES = java.util.Set.of(
      "image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml",
      "audio/mpeg", "audio/mp3", "audio/wav", "audio/ogg", "audio/flac",
      "audio/aac", "audio/webm", "audio/mp4",
      "video/mp4", "video/webm", "video/ogg"
  );

  @GetMapping("/{extractionId}/preview")
  @Operation(summary = "Preview an extracted file inline (browser-renderable types only)")
  public ResponseEntity<StreamingResponseBody> preview(
      @PathVariable UUID fileId, @PathVariable UUID extractionId) {

    ExtractedFileEntity entity =
        extractedFileRepository
            .findById(extractionId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Extracted file not found: " + extractionId));

    if (!entity.getFile().getId().equals(fileId)) {
      throw new ResourceNotFoundException("Extracted file not found: " + extractionId);
    }

    if (entity.getMinioPath() == null) {
      throw new ResourceNotFoundException("Extracted file not available: " + extractionId);
    }

    String mimeType =
        entity.getMimeType() != null ? entity.getMimeType() : "application/octet-stream";

    if (!INLINE_SAFE_MIME_TYPES.contains(mimeType)) {
      return ResponseEntity.status(415).build();
    }

    String filename = entity.getFilename() != null ? entity.getFilename() : "preview";

    StreamingResponseBody body =
        outputStream -> {
          try (InputStream in = storageService.downloadFile(entity.getMinioPath())) {
            in.transferTo(outputStream);
          }
        };

    return ResponseEntity.ok()
        .header(
            HttpHeaders.CONTENT_DISPOSITION,
            ContentDisposition.inline().filename(filename).build().toString())
        .contentType(MediaType.parseMediaType(mimeType))
        .body(body);
  }

  @GetMapping("/{extractionId}/download")
  @Operation(summary = "Download an extracted file")
  public ResponseEntity<StreamingResponseBody> download(
      @PathVariable UUID fileId, @PathVariable UUID extractionId) {

    ExtractedFileEntity entity =
        extractedFileRepository
            .findById(extractionId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Extracted file not found: " + extractionId));

    // Verify the entity belongs to the requested file
    if (!entity.getFile().getId().equals(fileId)) {
      throw new ResourceNotFoundException("Extracted file not found: " + extractionId);
    }

    if (entity.getMinioPath() == null) {
      throw new ResourceNotFoundException("Extracted file not available: " + extractionId);
    }

    String filename = entity.getFilename() != null ? entity.getFilename() : "extracted-file";
    String mimeType =
        entity.getMimeType() != null ? entity.getMimeType() : "application/octet-stream";

    StreamingResponseBody body =
        outputStream -> {
          try (InputStream in = storageService.downloadFile(entity.getMinioPath())) {
            in.transferTo(outputStream);
          }
        };

    return ResponseEntity.ok()
        .header(
            HttpHeaders.CONTENT_DISPOSITION,
            ContentDisposition.builder("attachment").filename(filename).build().toString())
        .contentType(MediaType.parseMediaType(mimeType))
        .body(body);
  }

  private ExtractedFileResponse toResponse(ExtractedFileEntity e) {
    return ExtractedFileResponse.builder()
        .id(e.getId())
        .conversationId(e.getConversation() != null ? e.getConversation().getId() : null)
        .filename(e.getFilename())
        .mimeType(e.getMimeType())
        .fileSize(e.getFileSize())
        .sha256(e.getSha256())
        .extractionMethod(e.getExtractionMethod())
        .skippedReason(e.getSkippedReason())
        .createdAt(e.getCreatedAt())
        .build();
  }
}
