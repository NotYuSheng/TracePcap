package com.tracepcap.file.controller;

import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.dto.MergeFilesRequest;
import com.tracepcap.file.entity.FileEntity.FileSource;
import com.tracepcap.file.service.FileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.io.InputStream;
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

  @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @Operation(summary = "Upload PCAP file", description = "Upload a PCAP file for analysis")
  public ResponseEntity<FileUploadResponse> uploadFile(
      @RequestParam("file") MultipartFile file,
      @RequestParam(value = "enableNdpi", defaultValue = "true") boolean enableNdpi,
      @RequestParam(value = "enableSuricata", defaultValue = "true") boolean enableSuricata,
      @RequestParam(value = "enableFileExtraction", defaultValue = "true")
          boolean enableFileExtraction,
      @RequestParam(value = "source", defaultValue = "ANALYSIS") FileSource source) {
    log.info(
        "Received file upload request: {} (ndpi={}, suricata={}, extraction={}, source={})",
        file.getOriginalFilename(),
        enableNdpi,
        enableSuricata,
        enableFileExtraction,
        source);

    FileUploadResponse response =
        fileService.uploadFile(file, enableNdpi, enableSuricata, enableFileExtraction, source);

    return ResponseEntity.status(HttpStatus.CREATED).body(response);
  }

  @GetMapping
  @Operation(summary = "Get all files", description = "Get all uploaded files with pagination")
  public ResponseEntity<PagedResponse<FileMetadataDto>> getAllFiles(
      @RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "20") int pageSize,
      @RequestParam(defaultValue = "uploadedAt,desc") String sort,
      @RequestParam(required = false) FileSource source) {

    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 20;

    // Parse sort parameter
    String[] sortParams = sort.split(",");
    Sort.Direction direction =
        sortParams.length > 1 && sortParams[1].equalsIgnoreCase("asc")
            ? Sort.Direction.ASC
            : Sort.Direction.DESC;
    // PageRequest is 0-indexed; the public API is 1-indexed (matches PagedResponse).
    Pageable pageable = PageRequest.of(page - 1, pageSize, Sort.by(direction, sortParams[0]));

    Page<FileMetadataDto> files = fileService.getAllFiles(pageable, source);

    return ResponseEntity.ok(
        PagedResponse.of(files.getContent(), files.getTotalElements(), page, pageSize));
  }

  @GetMapping("/{fileId}")
  @Operation(summary = "Get file metadata", description = "Get metadata for a specific file")
  public ResponseEntity<FileMetadataDto> getFileMetadata(@PathVariable String fileId) {

    FileMetadataDto metadata = fileService.getFileMetadata(UUID.fromString(fileId));

    return ResponseEntity.ok(metadata);
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
