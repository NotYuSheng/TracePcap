package com.tracepcap.file.repository;

import com.tracepcap.file.entity.FileEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Repository for FileEntity
 */
@Repository
public interface FileRepository extends JpaRepository<FileEntity, UUID> {

    /**
     * Find all files with pagination and sorting
     */
    Page<FileEntity> findAll(Pageable pageable);

    /**
     * Find files by status
     */
    Page<FileEntity> findByStatus(FileEntity.FileStatus status, Pageable pageable);

    /**
     * Find files uploaded before the specified timestamp (for cleanup)
     */
    List<FileEntity> findByUploadedAtBefore(LocalDateTime timestamp);
}
