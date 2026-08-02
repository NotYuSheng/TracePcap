package com.tracepcap.file.repository;

import com.tracepcap.file.entity.FileEntity;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** Repository for FileEntity */
@Repository
public interface FileRepository extends JpaRepository<FileEntity, UUID> {

  /** Find all files with pagination and sorting */
  Page<FileEntity> findAll(Pageable pageable);

  /** Find files by source with pagination */
  Page<FileEntity> findBySource(FileEntity.FileSource source, Pageable pageable);

  /** Find files by status */
  Page<FileEntity> findByStatus(FileEntity.FileStatus status, Pageable pageable);

  /** Find files uploaded before the specified timestamp (for cleanup) */
  List<FileEntity> findByUploadedAtBefore(LocalDateTime timestamp);

  /** Find files by source uploaded before the specified timestamp (for source-specific cleanup) */
  List<FileEntity> findBySourceAndUploadedAtBefore(FileEntity.FileSource source, LocalDateTime timestamp);

  /**
   * Find files whose packets are still stored and are older than the timestamp (for packet pruning,
   * #394). Excludes already-pruned files so each one is dropped once, not re-swept every cycle.
   */
  List<FileEntity> findByPacketsPrunedAtIsNullAndUploadedAtBefore(LocalDateTime timestamp);

  /** Find files in a given status uploaded before the timestamp (for stuck-file reconciliation) */
  List<FileEntity> findByStatusAndUploadedAtBefore(
      FileEntity.FileStatus status, LocalDateTime timestamp);

  /** Find the most recently uploaded file with the given SHA-256 hash */
  Optional<FileEntity> findFirstByFileHashOrderByUploadedAtDesc(String fileHash);
}
