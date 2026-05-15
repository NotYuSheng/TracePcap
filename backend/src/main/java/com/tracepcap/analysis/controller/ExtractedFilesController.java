package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.ExtractedFileResponse;
import com.tracepcap.analysis.entity.ExtractedFileEntity;
import com.tracepcap.analysis.repository.ExtractedFileRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.service.StorageService;
import io.swagger.v3.oas.annotations.Operation;
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
@RequestMapping("/api/files/{fileId}/extractions")
@RequiredArgsConstructor
public class ExtractedFilesController {

  private final ExtractedFileRepository extractedFileRepository;
  private final StorageService storageService;

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
