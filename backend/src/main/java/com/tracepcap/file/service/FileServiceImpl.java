package com.tracepcap.file.service;

import com.tracepcap.common.exception.DuplicateFileException;
import com.tracepcap.common.exception.InvalidFileException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.entity.FileEntity.FileSource;
import com.tracepcap.file.event.FileDeletedEvent;
import com.tracepcap.file.event.FileUploadedEvent;
import com.tracepcap.file.mapper.FileMapper;
import com.tracepcap.file.repository.FileRepository;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
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
public class FileServiceImpl implements FileService {

  private final FileRepository fileRepository;
  private final StorageService storageService;
  private final FileMapper fileMapper;
  private final ApplicationEventPublisher eventPublisher;

  private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(".pcap", ".pcapng", ".cap");
  /**
   * The largest capture we will accept, from {@code app.max-file-size} (#779).
   *
   * <p>Was a hardcoded 500 MB, which is how a 468 MB capture was accepted and then failed with an
   * OutOfMemoryError 25 minutes into parsing. The value the entrypoint derives from the memory
   * budget, and that {@code /system/limits} reports to the upload page, was never consulted here —
   * so the number the user was shown and the number actually enforced were different numbers.
   */
  private final long maxFileSize;

  public FileServiceImpl(
      FileRepository fileRepository,
      StorageService storageService,
      FileMapper fileMapper,
      ApplicationEventPublisher eventPublisher,
      @Value("${app.max-file-size:536870912}") long maxFileSize) {
    this.fileRepository = fileRepository;
    this.storageService = storageService;
    this.fileMapper = fileMapper;
    this.eventPublisher = eventPublisher;
    this.maxFileSize = maxFileSize;
  }


  @Override
  @Transactional
  public FileUploadResponse uploadFile(
      MultipartFile file,
      boolean enableNdpi,
      boolean enableSuricata,
      boolean enableFileExtraction,
      FileSource source) {
    log.info("Starting file upload: {}", file.getOriginalFilename());

    // Validate file
    validateFile(file);

    // Strip any Windows/Unix path prefix from the original filename (legacy IE sends full path)
    String originalFilename = stripPath(file.getOriginalFilename());

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
    String fileName = fileId.toString() + getFileExtension(originalFilename);
    log.info("DEBUG: Generated fileId: {}, fileName: {}", fileId, fileName);

    try {
      // Upload to MinIO
      String minioPath = storageService.uploadFile(file, fileName);
      log.info("DEBUG: Returned minioPath: {}", minioPath);

      // Count packets up front (best-effort) so the loading view can show a packet-based time
      // estimate immediately, before analysis has run. Overwritten with the exact count on completion.
      Integer packetCount = countPackets(file);

      // Save metadata to database
      FileEntity fileEntity =
          FileEntity.builder()
              .id(fileId)
              .fileName(originalFilename)
              .fileSize(file.getSize())
              .packetCount(packetCount)
              .minioPath(minioPath)
              .uploadedAt(LocalDateTime.now())
              .status(FileEntity.FileStatus.PROCESSING)
              .fileHash(fileHash)
              .source(source != null ? source : FileSource.ANALYSIS)
              .enableNdpi(enableNdpi)
              .enableSuricata(enableSuricata)
              .enableFileExtraction(enableFileExtraction)
              .build();

      fileEntity = fileRepository.save(fileEntity);
      log.info("File uploaded successfully: {} (ID: {})", originalFilename, fileId);
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
      log.error("Failed to upload file: {}", originalFilename, e);
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
  public Page<FileMetadataDto> getAllFiles(Pageable pageable, FileSource source) {
    if (source != null) {
      return fileRepository.findBySource(source, pageable).map(fileMapper::toMetadataDto);
    }
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

    // The FK cascade empties the packet partition but cannot remove the partition itself, so it
    // must be dropped explicitly or every deleted file leaves an empty table attached to `packets`
    // (#394). Announced rather than called directly: dropping it means reaching into `analysis`,
    // and `file` must not depend on `analysis` (LayerDependencyTest forbids the cycle).
    eventPublisher.publishEvent(new FileDeletedEvent(this, fileId));

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
    if (file.getSize() > maxFileSize) {
      throw new InvalidFileException(
          "File size exceeds maximum allowed size of " + (maxFileSize / 1024 / 1024) + "MB");
    }

    // Check file extension (strip any Windows/Unix path prefix before checking)
    String originalFilename = stripPath(file.getOriginalFilename());
    if (originalFilename == null || originalFilename.isBlank() || !hasValidExtension(originalFilename)) {
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

  /**
   * Strip any Windows or Unix directory prefix from a filename so that only the bare name is
   * stored. Legacy browsers (IE11) send the full client-side path (e.g. C:\Users\…\file.pcap)
   * in the Content-Disposition header; modern browsers send just the filename.
   */
  private String stripPath(String originalFilename) {
    if (originalFilename == null) return null;
    int lastSep = Math.max(originalFilename.lastIndexOf('/'), originalFilename.lastIndexOf('\\'));
    return lastSep >= 0 ? originalFilename.substring(lastSep + 1) : originalFilename;
  }

  @Override
  @Transactional
  public FileUploadResponse mergeFiles(
      List<UUID> fileIds,
      String mergedFileName,
      boolean enableNdpi,
      boolean enableSuricata,
      boolean enableFileExtraction) {
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
      Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();

      // Drain stdout/stderr in a background thread to prevent blocking
      final StringBuilder processOutput = new StringBuilder();
      Thread drainThread =
          new Thread(
              () -> {
                try {
                  processOutput.append(new String(process.getInputStream().readAllBytes()));
                } catch (IOException ignored) {
                }
              });
      drainThread.setDaemon(true);
      drainThread.start();

      boolean finished = process.waitFor(5, TimeUnit.MINUTES);
      drainThread.join(5000);
      if (!finished) {
        process.destroyForcibly();
        throw new InvalidFileException("mergecap timed out after 5 minutes");
      }
      int exitCode = process.exitValue();
      if (exitCode != 0) {
        throw new InvalidFileException("mergecap failed (exit " + exitCode + "): " + processOutput);
      }

      // Compute hash by streaming the merged file (avoids loading it fully into memory)
      String fileHash = computeSha256FromFile(tempOutput);

      Optional<FileEntity> existing =
          fileRepository.findFirstByFileHashOrderByUploadedAtDesc(fileHash);
      if (existing.isPresent()) {
        throw new DuplicateFileException(existing.get().getId());
      }

      // Use caller-supplied name or auto-generate from source names
      String mergedName =
          (mergedFileName != null && !mergedFileName.isBlank())
              ? sanitizeMergedFileName(mergedFileName)
              : buildAutoMergedName(fileIds);

      // Stream-upload the merged file to MinIO (avoids loading it fully into memory)
      UUID newFileId = UUID.randomUUID();
      String storedName = newFileId + ".pcap";
      storageService.uploadFile(tempOutput, storedName, "application/vnd.tcpdump.pcap");

      // Persist metadata
      FileEntity fileEntity =
          FileEntity.builder()
              .id(newFileId)
              .fileName(mergedName)
              .fileSize(tempOutput.length())
              .packetCount(countPackets(tempOutput))
              .minioPath(storedName)
              .uploadedAt(LocalDateTime.now())
              .status(FileEntity.FileStatus.PROCESSING)
              .fileHash(fileHash)
              .enableNdpi(enableNdpi)
              .enableSuricata(enableSuricata)
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
        try {
          Files.deleteIfExists(f.toPath());
        } catch (IOException ignored) {
        }
      }
      if (tempOutput != null) {
        try {
          Files.deleteIfExists(tempOutput.toPath());
        } catch (IOException ignored) {
        }
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

  private String computeSha256FromFile(File file) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      try (InputStream is =
          new DigestInputStream(new BufferedInputStream(new FileInputStream(file)), digest)) {
        byte[] buf = new byte[8192];
        while (is.read(buf) != -1) {
          /* drain to feed the digest */
        }
      }
      return HexFormat.of().formatHex(digest.digest());
    } catch (Exception e) {
      throw new InvalidFileException("Could not compute hash of merged file", e);
    }
  }

  // capinfos machine-readable output line: "Number of packets:   21364"
  private static final Pattern PACKET_COUNT_PATTERN =
      Pattern.compile("Number of packets:\\s*(\\d+)");

  // Short bound for the best-effort packet count: capinfos -c only scans record headers and is fast
  // even on large files, and this runs on the request thread inside the upload/merge transaction, so
  // it must never hold resources long. On timeout we give up and fall back to the size-based estimate.
  private static final int CAPINFOS_TIMEOUT_SECONDS = 15;

  /**
   * Counts packets in an uploaded capture by streaming it through {@code capinfos -M -c -} (reads
   * stdin, ~ms even for large files). Used to compute a packet-count-based analysis time estimate up
   * front — cost tracks packets, not bytes. Best-effort: any failure returns {@code null} and the
   * estimate falls back to a size-based one. Never throws.
   */
  private Integer countPackets(MultipartFile file) {
    Process process = null;
    try {
      process =
          new ProcessBuilder("capinfos", "-M", "-c", "-").redirectErrorStream(false).start();
      final Process p = process;
      // Drain stdout on a daemon thread so waitFor's timeout is honoured even if capinfos hangs
      // without closing stdout (a blocking readAllBytes here would bypass the timeout entirely).
      StringBuilder output = new StringBuilder();
      Thread reader = drainStdout(p, output);
      // Feed the capture into capinfos stdin on a daemon thread so we can read stdout concurrently
      // (avoids a pipe-buffer deadlock). A broken pipe (capinfos closing stdin early) is expected.
      Thread feeder =
          new Thread(
              () -> {
                try (InputStream in = file.getInputStream();
                    OutputStream out = p.getOutputStream()) {
                  in.transferTo(out);
                } catch (IOException ignored) {
                  // capinfos may close stdin before consuming everything — not an error for -c
                }
              });
      feeder.setDaemon(true);
      feeder.start();

      if (!process.waitFor(CAPINFOS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        return null;
      }
      feeder.join(2000);
      reader.join(2000);
      if (process.exitValue() != 0) return null;
      Matcher m = PACKET_COUNT_PATTERN.matcher(output.toString());
      return m.find() ? Integer.parseInt(m.group(1)) : null;
    } catch (Exception e) {
      log.warn("capinfos packet count failed for {}: {}", file.getOriginalFilename(), e.getMessage());
      if (process != null) process.destroyForcibly();
      return null;
    }
  }

  /** Packet count for a local capture file via {@code capinfos -M -c <path>}. Best-effort. */
  private Integer countPackets(File file) {
    Process process = null;
    try {
      process =
          new ProcessBuilder("capinfos", "-M", "-c", file.getAbsolutePath())
              .redirectErrorStream(false)
              .start();
      // Drain stdout on a daemon thread so a hung capinfos can't block past waitFor's timeout.
      StringBuilder output = new StringBuilder();
      Thread reader = drainStdout(process, output);
      if (!process.waitFor(CAPINFOS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        return null;
      }
      reader.join(2000);
      if (process.exitValue() != 0) return null;
      Matcher m = PACKET_COUNT_PATTERN.matcher(output.toString());
      return m.find() ? Integer.parseInt(m.group(1)) : null;
    } catch (Exception e) {
      log.warn("capinfos packet count failed for {}: {}", file.getName(), e.getMessage());
      if (process != null) process.destroyForcibly();
      return null;
    }
  }

  /** Reads a process's stdout into {@code sink} on a started daemon thread (UTF-8). */
  private Thread drainStdout(Process process, StringBuilder sink) {
    Thread reader =
        new Thread(
            () -> {
              try (InputStream in = process.getInputStream()) {
                sink.append(new String(in.readAllBytes(), StandardCharsets.UTF_8));
              } catch (IOException ignored) {
                // best-effort: caller treats missing output as an unparseable count → null
              }
            });
    reader.setDaemon(true);
    reader.start();
    return reader;
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
