package com.tracepcap.file.controller;

import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.service.FileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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

import java.io.InputStream;
import java.util.UUID;

/**
 * REST controller for file management operations
 */
@Slf4j
@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
@Tag(name = "File Management", description = "APIs for PCAP file upload, download, and management")
public class FileController {

    private final FileService fileService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload PCAP file", description = "Upload a PCAP file for analysis")
    public ResponseEntity<FileUploadResponse> uploadFile(
            @RequestParam("file") MultipartFile file) {
        log.info("Received file upload request: {}", file.getOriginalFilename());

        FileUploadResponse response = fileService.uploadFile(file);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    @Operation(summary = "Get all files", description = "Get all uploaded files with pagination")
    public ResponseEntity<Page<FileMetadataDto>> getAllFiles(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "uploadedAt,desc") String sort) {

        // Parse sort parameter
        String[] sortParams = sort.split(",");
        Sort.Direction direction = sortParams.length > 1 && sortParams[1].equalsIgnoreCase("asc")
                ? Sort.Direction.ASC
                : Sort.Direction.DESC;
        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortParams[0]));

        Page<FileMetadataDto> files = fileService.getAllFiles(pageable);

        return ResponseEntity.ok(files);
    }

    @GetMapping("/{fileId}")
    @Operation(summary = "Get file metadata", description = "Get metadata for a specific file")
    public ResponseEntity<FileMetadataDto> getFileMetadata(
            @PathVariable String fileId) {

        FileMetadataDto metadata = fileService.getFileMetadata(UUID.fromString(fileId));

        return ResponseEntity.ok(metadata);
    }

    @GetMapping("/{fileId}/download")
    @Operation(summary = "Download file", description = "Download a PCAP file")
    public ResponseEntity<InputStreamResource> downloadFile(
            @PathVariable String fileId) {

        UUID uuid = UUID.fromString(fileId);
        InputStream fileStream = fileService.downloadFile(uuid);
        String fileName = fileService.getFileName(uuid);

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"");
        headers.add(HttpHeaders.CONTENT_TYPE, "application/vnd.tcpdump.pcap");

        return ResponseEntity.ok()
                .headers(headers)
                .body(new InputStreamResource(fileStream));
    }

    @DeleteMapping("/{fileId}")
    @Operation(summary = "Delete file", description = "Delete a PCAP file")
    public ResponseEntity<Void> deleteFile(
            @PathVariable String fileId) {

        fileService.deleteFile(UUID.fromString(fileId));

        return ResponseEntity.noContent().build();
    }
}
