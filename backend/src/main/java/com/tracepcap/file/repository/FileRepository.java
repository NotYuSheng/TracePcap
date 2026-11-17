package com.tracepcap.file.repository;

import com.tracepcap.file.entity.FileEntity;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Repository;

/** Repository for FileEntity */
@Repository
public interface FileRepository
    extends JpaRepository<FileEntity, UUID>, JpaSpecificationExecutor<FileEntity> {

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
  /** The upload with this hash (#885); re-analysis versions share it and don't count. */
  Optional<FileEntity> findFirstByFileHashAndIsVersionFalseOrderByUploadedAtDesc(String fileHash);

  /** A capture's versions (#915 phase 3), oldest first. */
  List<FileEntity> findByDerivedFromOrderByUploadedAtAsc(java.util.UUID derivedFrom);

  /** Captures in this analysis state whose background story is in one of these states. */
  List<FileEntity> findByStatusAndStoryStatusIn(
      FileEntity.FileStatus status, java.util.Collection<String> storyStatuses);

  @org.springframework.data.jpa.repository.Query("SELECT f.id FROM FileEntity f WHERE f.status = :status")
  List<java.util.UUID> findIdsByStatus(
      @org.springframework.data.repository.query.Param("status") FileEntity.FileStatus status);

  /** Ids of every capture whose analysis completed (#925: the captures rules apply to). */
  default List<java.util.UUID> findCompletedIds() {
    return findIdsByStatus(FileEntity.FileStatus.COMPLETED);
  }

  /**
   * Records how far the background story got, touching only those two columns: the file row is
   * also written by analysis and the UI, and a whole-entity save from a long-running story job
   * would put back whatever it read minutes earlier.
   */
  @Modifying
  @Transactional
  @Query("UPDATE FileEntity f SET f.storyStatus = :status, f.storyError = :error WHERE f.id = :id")
  int updateStoryStatus(
      @Param("id") UUID id, @Param("status") String status, @Param("error") String error);
}
