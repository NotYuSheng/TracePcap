package com.tracepcap.file.controller;

import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.dto.MergeFilesRequest;
import com.tracepcap.file.entity.FileEntity.FileSource;
import com.tracepcap.file.entity.FileEntity.FileStatus;
import com.tracepcap.file.repository.FileListFilter;
import com.tracepcap.file.dto.ExpiryRequest;
import com.tracepcap.file.service.FileFavouriteService;
import com.tracepcap.file.service.FileService;
import com.tracepcap.common.settings.EditablePolicy;
import com.tracepcap.common.settings.RuntimePolicy;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.io.InputStream;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/** REST controller for file management operations */
@Slf4j
@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(name = "File Management", description = "APIs for PCAP file upload, download, and management")
public class FileController {

  private final FileService fileService;
  private final FileFavouriteService favouriteService;
  private final RuntimePolicy runtimePolicy;

  @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @Operation(summary = "Upload PCAP file", description = "Upload a PCAP file for analysis")
  public ResponseEntity<FileUploadResponse> uploadFile(
      @RequestParam("file") MultipartFile file,
      @RequestParam(value = "enableNdpi", defaultValue = "true") boolean enableNdpi,
      @RequestParam(value = "enableSuricata", defaultValue = "true") boolean enableSuricata,
      @RequestParam(value = "enableFileExtraction", defaultValue = "true")
          boolean enableFileExtraction,
      @RequestParam(value = "source", defaultValue = "ANALYSIS") FileSource source,
      @RequestParam(value = "generateStory", defaultValue = "false") boolean generateStory,
      @RequestParam(value = "expires", defaultValue = "true") boolean expires) {
    log.info(
        "Received file upload request: {} (ndpi={}, suricata={}, extraction={}, source={}, story={},"
            + " expires={})",
        file.getOriginalFilename(),
        enableNdpi,
        enableSuricata,
        enableFileExtraction,
        source,
        generateStory,
        expires);

    FileUploadResponse response =
        fileService.uploadFile(
            file, enableNdpi, enableSuricata, enableFileExtraction, source, generateStory, !expires);

    return ResponseEntity.status(HttpStatus.CREATED).body(response);
  }

  @GetMapping
  @Operation(
      summary = "Get all files",
      description =
          "Get all uploaded files with pagination. Optional filters: search (name contains),"
              + " status, fileIds (only these), excludeFileIds, uploadedBefore (epoch ms),"
              + " expiringBefore (epoch ms: deleted before then, by its own expiry or the retention"
              + " window), favourite (only the caller's favourites).")
  public ResponseEntity<PagedResponse<FileMetadataDto>> getAllFiles(
      @RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "20") int pageSize,
      @RequestParam(defaultValue = "uploadedAt,desc") String sort,
      @RequestParam(required = false) FileSource source,
      @RequestParam(required = false) String search,
      @RequestParam(required = false) List<FileStatus> status,
      @RequestParam(required = false) List<UUID> fileIds,
      @RequestParam(required = false) List<UUID> excludeFileIds,
      @RequestParam(required = false) Long uploadedBefore,
      @RequestParam(required = false) Long expiringBefore,
      @RequestParam(required = false) Boolean favourite) {

    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 20;
    else if (pageSize > 100) pageSize = 100; // cap to bound DB load / response size

    // Parse sort parameter; fall back to a stable default for blank/malformed input
    // (e.g. "?sort=" or "?sort=,asc") rather than letting an empty field reach Sort.by().
    String[] sortParams = sort == null ? new String[0] : sort.split(",");
    String sortField =
        sortParams.length > 0 && !sortParams[0].isBlank() ? sortParams[0].trim() : "uploadedAt";
    Sort.Direction direction =
        sortParams.length > 1 && "asc".equalsIgnoreCase(sortParams[1].trim())
            ? Sort.Direction.ASC
            : Sort.Direction.DESC;
    // PageRequest is 0-indexed; the public API is 1-indexed (matches PagedResponse).
    Pageable pageable = PageRequest.of(page - 1, pageSize, Sort.by(direction, sortField));

    java.util.Set<UUID> favourites = favouriteService.favouriteIds();
    // Favourites only: the given ids narrowed to the caller's favourites (all of them when none given).
    List<UUID> ids = fileIds;
    if (Boolean.TRUE.equals(favourite)) {
      ids = (fileIds == null ? favourites.stream() : fileIds.stream().filter(favourites::contains)).toList();
    }
    FileListFilter filter =
        new FileListFilter(
            source,
            search,
            status,
            ids,
            excludeFileIds,
            uploadedBefore == null
                ? null
                : LocalDateTime.ofInstant(Instant.ofEpochMilli(uploadedBefore), ZoneId.systemDefault()),
            expiringBefore == null
                ? null
                : LocalDateTime.ofInstant(Instant.ofEpochMilli(expiringBefore), ZoneId.systemDefault()),
            expiringBefore == null ? null : runtimePolicy.getInt(EditablePolicy.FILE_RETENTION_HOURS));
    Page<FileMetadataDto> files = fileService.getAllFiles(pageable, filter);
    files.getContent().forEach(f -> f.setFavourite(favourites.contains(UUID.fromString(f.getFileId()))));

    return ResponseEntity.ok(
        PagedResponse.of(files.getContent(), files.getTotalElements(), page, pageSize));
  }

  @GetMapping("/{fileId}")
  @Operation(summary = "Get file metadata", description = "Get metadata for a specific file")
  public ResponseEntity<FileMetadataDto> getFileMetadata(@PathVariable String fileId) {

    FileMetadataDto metadata = fileService.getFileMetadata(UUID.fromString(fileId));
    metadata.setFavourite(favouriteService.favouriteIds().contains(UUID.fromString(fileId)));

    return ResponseEntity.ok(metadata);
  }

  @PutMapping("/{fileId}/favourite")
  @Operation(
      summary = "Mark a capture as a favourite",
      description = "Personal: the caller's account, or the shared profile when login is off. Idempotent.")
  public ResponseEntity<Void> addFavourite(@PathVariable UUID fileId) {
    favouriteService.add(fileId);
    return ResponseEntity.noContent().build();
  }

  @DeleteMapping("/{fileId}/favourite")
  @Operation(summary = "Unmark a favourite capture", description = "Idempotent.")
  public ResponseEntity<Void> removeFavourite(@PathVariable UUID fileId) {
    favouriteService.remove(fileId);
    return ResponseEntity.noContent().build();
  }

  @PutMapping("/{fileId}/expiry")
  @Operation(
      summary = "Change when a capture is deleted",
      description =
          "keepForever: never. Else expiresAt (epoch ms, in the future, at most a year away) keeps it"
              + " until then; null puts it back on the retention window.")
  public FileMetadataDto setExpiry(@PathVariable UUID fileId, @RequestBody ExpiryRequest request) {
    LocalDateTime at =
        request.getExpiresAt() == null
            ? null
            : LocalDateTime.ofInstant(Instant.ofEpochMilli(request.getExpiresAt()), ZoneId.systemDefault());
    FileMetadataDto dto = fileService.setExpiry(fileId, request.isKeepForever(), at);
    dto.setFavourite(favouriteService.favouriteIds().contains(fileId));
    return dto;
  }

  @PostMapping("/{fileId}/reanalyses")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Re-analyse a capture with other options, as a new version",
      description =
          "Creates a new capture (its own copy in storage, derivedFrom the original) and analyses it"
              + " with the given options. The original and its analysis are kept. The capture's own"
              + " detection rules are copied to the version.")
  public com.tracepcap.file.dto.FileUploadResponse reanalyse(
      @PathVariable UUID fileId, @RequestBody com.tracepcap.file.dto.ReanalyseRequest request) {
    return fileService.reanalyse(
        fileId, request.isEnableNdpi(), request.isEnableSuricata(), request.isEnableFileExtraction());
  }

  @GetMapping("/{fileId}/versions")
  @Operation(summary = "A capture and its re-analysis versions, the original first")
  public java.util.List<FileMetadataDto> versions(@PathVariable UUID fileId) {
    return fileService.versions(fileId);
  }

  @GetMapping("/{fileId}/download")
  @Operation(summary = "Download file", description = "Download a PCAP file")
  public ResponseEntity<InputStreamResource> downloadFile(@PathVariable String fileId) {

    UUID uuid = UUID.fromString(fileId);
    InputStream fileStream = fileService.downloadFile(uuid);
    String fileName = fileService.getFileName(uuid);

    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"");
    headers.add(HttpHeaders.CONTENT_TYPE, "application/vnd.tcpdump.pcap");

    return ResponseEntity.ok().headers(headers).body(new InputStreamResource(fileStream));
  }

  @DeleteMapping("/{fileId}")
  @Operation(summary = "Delete file", description = "Delete a PCAP file")
  public ResponseEntity<Void> deleteFile(@PathVariable String fileId) {

    fileService.deleteFile(UUID.fromString(fileId));

    return ResponseEntity.noContent().build();
  }

  @PostMapping("/merge")
  @Operation(
      summary = "Merge PCAP files",
      description = "Merge two or more PCAP files into a single new file and trigger analysis")
  public ResponseEntity<FileUploadResponse> mergeFiles(
      @Valid @RequestBody MergeFilesRequest request,
      @RequestParam(value = "enableNdpi", defaultValue = "true") boolean enableNdpi,
      @RequestParam(value = "enableSuricata", defaultValue = "true") boolean enableSuricata,
      @RequestParam(value = "enableFileExtraction", defaultValue = "true")
          boolean enableFileExtraction) {

    log.info(
        "Received merge request for {} files",
        request.getFileIds() != null ? request.getFileIds().size() : 0);

    FileUploadResponse response =
        fileService.mergeFiles(
            request.getFileIds(),
            request.getMergedFileName(),
            enableNdpi,
            enableSuricata,
            enableFileExtraction);

    return ResponseEntity.status(HttpStatus.CREATED).body(response);
  }
}
