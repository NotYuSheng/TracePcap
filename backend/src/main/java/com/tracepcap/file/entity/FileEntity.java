package com.tracepcap.file.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entity representing an uploaded PCAP file
 */
@Entity
@Table(name = "files")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FileEntity {

    @Id
    private UUID id;

    @Column(name = "file_name", nullable = false)
    private String fileName;

    @Column(name = "file_size", nullable = false)
    private Long fileSize;

    @Column(name = "minio_path", nullable = false, length = 512)
    private String minioPath;

    @Column(name = "uploaded_at", nullable = false)
    private LocalDateTime uploadedAt;

    @Column(name = "status", nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private FileStatus status;

    @Column(name = "packet_count")
    private Integer packetCount;

    @Column(name = "total_bytes")
    private Long totalBytes;

    @Column(name = "duration")
    private Long duration;

    @Column(name = "start_time")
    private LocalDateTime startTime;

    @Column(name = "end_time")
    private LocalDateTime endTime;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    /**
     * File processing status
     */
    public enum FileStatus {
        UPLOADING,
        PROCESSING,
        COMPLETED,
        FAILED
    }
}
