package com.tracepcap.file.service;

import com.tracepcap.common.exception.DuplicateFileException;
import com.tracepcap.common.exception.InvalidFileException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.event.FileUploadedEvent;
import com.tracepcap.file.mapper.FileMapper;
import com.tracepcap.file.repository.FileRepository;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

/** Implementation of FileService */
@Slf4j
@Service
@RequiredArgsConstructor
public class FileServiceImpl implements FileService {

  private final FileRepository fileRepository;
  private final StorageService storageService;
  private final FileMapper fileMapper;
  private final ApplicationEventPublisher eventPublisher;

  private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(".pcap", ".pcapng", ".cap");
  private static final long MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB

  @Override
  @Transactional
  public FileUploadResponse uploadFile(
      MultipartFile file, boolean enableNdpi, boolean enableFileExtraction) {
    log.info("Starting file upload: {}", file.getOriginalFilename());

    // Validate file
    validateFile(file);

    // Compute SHA-256 hash to detect duplicates
    String fileHash = computeSha256(file);

    // Reject if a file with the same hash already exists
    Optional<FileEntity> existing =
        fileRepository.findFirstByFileHashOrderByUploadedAtDesc(fileHash);
    if (existing.isPresent()) {
      throw new DuplicateFileException(existing.get().getId());
    }

    // Generate unique ID and file name
    UUID fileId = UUID.randomUUID();
    String fileName = fileId.toString() + getFileExtension(file.getOriginalFilename());
    log.info("DEBUG: Generated fileId: {}, fileName: {}", fileId, fileName);

    try {
      // Upload to MinIO
      String minioPath = storageService.uploadFile(file, fileName);
      log.info("DEBUG: Returned minioPath: {}", minioPath);

      // Save metadata to database
      FileEntity fileEntity =
          FileEntity.builder()
              .id(fileId)
              .fileName(file.getOriginalFilename())
              .fileSize(file.getSize())
              .minioPath(minioPath)
              .uploadedAt(LocalDateTime.now())
              .status(FileEntity.FileStatus.PROCESSING)
              .fileHash(fileHash)
              .enableNdpi(enableNdpi)
              .enableFileExtraction(enableFileExtraction)
              .build();

      fileEntity = fileRepository.save(fileEntity);
      log.info("File uploaded successfully: {} (ID: {})", file.getOriginalFilename(), fileId);
      log.info(
          "DEBUG: About to publish event - fileId value: {}, fileEntity.getId(): {}",
          fileId,
          fileEntity.getId());

      // Publish event - listener will trigger async analysis AFTER transaction commits
      log.info("Publishing file uploaded event for file: {}", fileId);
      eventPublisher.publishEvent(new FileUploadedEvent(this, fileId));
      log.info("DEBUG: Event published with fileId: {}", fileId);

      return fileMapper.toUploadResponse(fileEntity);

    } catch (Exception e) {
      log.error("Failed to upload file: {}", file.getOriginalFilename(), e);
      throw new InvalidFileException("Failed to upload file: " + e.getMessage(), e);
    }
  }

  @Override
  @Transactional(readOnly = true)
  public FileMetadataDto getFileMetadata(UUID fileId) {
    FileEntity fileEntity =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File", "id", fileId));

    return fileMapper.toMetadataDto(fileEntity);
  }

  @Override
  @Transactional(readOnly = true)
  public Page<FileMetadataDto> getAllFiles(Pageable pageable) {
    return fileRepository.findAll(pageable).map(fileMapper::toMetadataDto);
  }

  @Override
  @Transactional(readOnly = true)
  public InputStream downloadFile(UUID fileId) {
    FileEntity fileEntity =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File", "id", fileId));

    return storageService.downloadFile(fileEntity.getMinioPath());
  }

  @Override
  @Transactional
  public void deleteFile(UUID fileId) {
    FileEntity fileEntity =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File", "id", fileId));

    // Delete from MinIO
    storageService.deleteFile(fileEntity.getMinioPath());

    // Delete from database
    fileRepository.delete(fileEntity);

    log.info("File deleted successfully: {} (ID: {})", fileEntity.getFileName(), fileId);
  }

  @Override
  @Transactional(readOnly = true)
  public String getFileName(UUID fileId) {
    FileEntity fileEntity =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File", "id", fileId));

    return fileEntity.getFileName();
  }

  @Override
  public FileEntity getFileById(UUID fileId) {
    return fileRepository
        .findById(fileId)
        .orElseThrow(() -> new ResourceNotFoundException("File", "id", fileId));
  }

  /** Validate uploaded file */
  private void validateFile(MultipartFile file) {
    // Check if file is empty
    if (file.isEmpty()) {
      throw new InvalidFileException("File is empty");
    }

    // Check file size
    if (file.getSize() > MAX_FILE_SIZE) {
      throw new InvalidFileException("File size exceeds maximum allowed size of 500MB");
    }

    // Check file extension
    String originalFilename = file.getOriginalFilename();
    if (originalFilename == null || !hasValidExtension(originalFilename)) {
      throw new InvalidFileException(
          "Invalid file type. Only .pcap, .pcapng, and .cap files are supported");
    }
  }

  /** Check if file has valid extension */
  private boolean hasValidExtension(String filename) {
    String extension = getFileExtension(filename).toLowerCase();
    return ALLOWED_EXTENSIONS.contains(extension);
  }

  /** Get file extension from filename */
  private String getFileExtension(String filename) {
    int lastDotIndex = filename.lastIndexOf('.');
    return lastDotIndex > 0 ? filename.substring(lastDotIndex) : "";
  }

  @Override
  @Transactional
  public FileUploadResponse mergeFiles(
      List<UUID> fileIds, String mergedFileName, boolean enableNdpi, boolean enableFileExtraction) {
    if (fileIds == null || fileIds.size() < 2) {
      throw new InvalidFileException("At least two files are required for merging");
    }

    log.info("Starting PCAP merge for {} files: {}", fileIds.size(), fileIds);

    List<File> tempInputs = new ArrayList<>();
    File tempOutput = null;

    try {
      // Download each source file to a local temp file
      for (UUID fileId : fileIds) {
        FileEntity entity = getFileById(fileId);
        File tmp = File.createTempFile("merge-input-" + fileId, ".pcap");
        storageService.downloadFileToLocal(entity.getMinioPath(), tmp);
        tempInputs.add(tmp);
      }

      // Build mergecap command
      tempOutput = File.createTempFile("merge-output-", ".pcap");
      List<String> cmd = new ArrayList<>();
      cmd.add("mergecap");
      cmd.add("-w");
      cmd.add(tempOutput.getAbsolutePath());
      for (File f : tempInputs) {
        cmd.add(f.getAbsolutePath());
      }

      log.info("Running mergecap: {}", cmd);
      Process process = new ProcessBuilder(cmd)
          .redirectErrorStream(true)
          .start();

      String output = new String(process.getInputStream().readAllBytes());
      int exitCode = process.waitFor();
      if (exitCode != 0) {
        throw new InvalidFileException("mergecap failed (exit " + exitCode + "): " + output);
      }

      // Compute hash of the merged file to detect duplicates
      byte[] mergedBytes = Files.readAllBytes(tempOutput.toPath());
      String fileHash = computeSha256FromBytes(mergedBytes);

      Optional<FileEntity> existing =
          fileRepository.findFirstByFileHashOrderByUploadedAtDesc(fileHash);
      if (existing.isPresent()) {
        throw new DuplicateFileException(existing.get().getId());
      }

      // Use caller-supplied name or auto-generate from source names
      String mergedName = (mergedFileName != null && !mergedFileName.isBlank())
          ? sanitizeMergedFileName(mergedFileName)
          : buildAutoMergedName(fileIds);

      // Upload merged file to MinIO
      UUID newFileId = UUID.randomUUID();
      String storedName = newFileId + ".pcap";
      storageService.uploadBytes(mergedBytes, storedName, "application/vnd.tcpdump.pcap");

      // Persist metadata
      FileEntity fileEntity =
          FileEntity.builder()
              .id(newFileId)
              .fileName(mergedName)
              .fileSize((long) mergedBytes.length)
              .minioPath(storedName)
              .uploadedAt(LocalDateTime.now())
              .status(FileEntity.FileStatus.PROCESSING)
              .fileHash(fileHash)
              .enableNdpi(enableNdpi)
              .enableFileExtraction(enableFileExtraction)
              .build();

      fileEntity = fileRepository.save(fileEntity);
      log.info("Merged PCAP saved: {} (ID: {})", mergedName, newFileId);

      // Trigger async analysis
      eventPublisher.publishEvent(new FileUploadedEvent(this, newFileId));

      return fileMapper.toUploadResponse(fileEntity);

    } catch (InvalidFileException | DuplicateFileException e) {
      throw e;
    } catch (Exception e) {
      log.error("Failed to merge PCAP files", e);
      throw new InvalidFileException("Failed to merge files: " + e.getMessage(), e);
    } finally {
      for (File f : tempInputs) {
        try { Files.deleteIfExists(f.toPath()); } catch (IOException ignored) {}
      }
      if (tempOutput != null) {
        try { Files.deleteIfExists(tempOutput.toPath()); } catch (IOException ignored) {}
      }
    }
  }

  private String buildAutoMergedName(List<UUID> fileIds) {
    final int MAX_PART = 20;
    final int MAX_SHOWN = 3;
    List<String> parts = new ArrayList<>();
    for (int i = 0; i < Math.min(MAX_SHOWN, fileIds.size()); i++) {
      try {
        String base = getFileById(fileIds.get(i)).getFileName().replaceFirst("\\.[^.]+$", "");
        parts.add(base.length() > MAX_PART ? base.substring(0, MAX_PART) : base);
      } catch (Exception ignored) {
        parts.add(fileIds.get(i).toString().substring(0, 8));
      }
    }
    String joined = String.join("+", parts);
    if (fileIds.size() > MAX_SHOWN) {
      joined += "+" + (fileIds.size() - MAX_SHOWN) + "_more";
    }
    return "merged_" + joined + ".pcap";
  }

  private String sanitizeMergedFileName(String name) {
    // Strip any path separators and control characters, ensure .pcap extension
    String safe = name.replaceAll("[/\\\\<>:\"|?*\\p{Cntrl}]", "_").trim();
    if (safe.isBlank()) {
      safe = "merged";
    }
    // Ensure it ends with .pcap
    if (!safe.toLowerCase().endsWith(".pcap")) {
      safe = safe + ".pcap";
    }
    return safe;
  }

  private String computeSha256FromBytes(byte[] data) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(digest.digest(data));
    } catch (Exception e) {
      throw new InvalidFileException("Could not compute hash of merged file", e);
    }
  }

  /** Compute SHA-256 hex digest of the uploaded file using a streaming approach */
  private String computeSha256(MultipartFile file) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      try (InputStream is = file.getInputStream()) {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = is.read(buffer)) != -1) {
          digest.update(buffer, 0, bytesRead);
        }
      }
      return HexFormat.of().formatHex(digest.digest());
    } catch (Exception e) {
      log.error(
          "Failed to compute SHA-256 for file {}: {}", file.getOriginalFilename(), e.getMessage());
      throw new InvalidFileException("Could not process file: failed to compute hash", e);
    }
  }
}
