package com.tracepcap.file.service;

import com.tracepcap.common.exception.InvalidFileException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.event.FileUploadedEvent;
import com.tracepcap.file.mapper.FileMapper;
import com.tracepcap.file.repository.FileRepository;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
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
  public FileUploadResponse uploadFile(MultipartFile file) {
    log.info("Starting file upload: {}", file.getOriginalFilename());

    // Validate file
    validateFile(file);

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

    // TODO: Validate PCAP file format (magic bytes)
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
}
