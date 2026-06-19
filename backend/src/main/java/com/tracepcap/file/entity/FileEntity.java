package com.tracepcap.file.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

/** Entity representing an uploaded PCAP file */
@Entity
@Table(name = "files")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FileEntity {

  @Id private UUID id;

  @Column(name = "file_name", nullable = false)
  private String fileName;

  @Column(name = "file_size", nullable = false)
  private Long fileSize;

  @Column(name = "minio_path", nullable = false, length = 512)
  private String minioPath;

  @Column(name = "file_hash", length = 64)
  private String fileHash;

  @Builder.Default
  @Column(name = "source", nullable = false, length = 20)
  @Enumerated(EnumType.STRING)
  private FileSource source = FileSource.ANALYSIS;

  @Builder.Default
  @Column(name = "enable_ndpi", nullable = false)
  private boolean enableNdpi = true;

  @Builder.Default
  @Column(name = "enable_file_extraction", nullable = false)
  private boolean enableFileExtraction = true;

  /**
   * Comma-separated conversation IDs whose raw stream hit the per-stream match cap during
   * extraction (more embedded files may exist). Null/empty when the cap was never reached.
   */
  @Column(name = "extraction_match_limit_conv_ids", columnDefinition = "text")
  private String extractionMatchLimitConvIds;

  /** Total non-HTTP file-bearing streams that were not scanned because of the conversation cap. */
  @Builder.Default
  @Column(name = "extraction_conversation_limit_skipped_count", nullable = false)
  private int extractionConversationLimitSkippedCount = 0;

  /** Comma-separated (capped) conversation IDs of streams skipped by the conversation cap. */
  @Column(name = "extraction_conversation_limit_skipped_ids", columnDefinition = "text")
  private String extractionConversationLimitSkippedIds;

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

  /** Upload source — controls listing visibility and retention policy */
  public enum FileSource {
    ANALYSIS,
    MONITOR
  }

  /** File processing status */
  public enum FileStatus {
    UPLOADING,
    PROCESSING,
    COMPLETED,
    FAILED
  }
}
