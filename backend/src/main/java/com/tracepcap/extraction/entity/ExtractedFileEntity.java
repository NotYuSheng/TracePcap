package com.tracepcap.extraction.entity;

import com.tracepcap.file.entity.FileEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "extracted_files")
@Getter
@Setter
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExtractedFileEntity {

  @EqualsAndHashCode.Include
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ToString.Exclude
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id", nullable = false)
  private FileEntity file;

  /**
   * The conversation this file was carved from, as an id rather than a JPA association (#512).
   *
   * <p>Same {@code conversation_id} column, so no migration: the association only ever existed to
   * set the FK, and the writer already held the UUID and used {@code getReference} to turn it back
   * into an entity. Holding the id keeps the extraction module off {@code analysis.entity} and
   * removes that round trip.
   */
  @Column(name = "conversation_id")
  private UUID conversationId;

  @Column(name = "filename", length = 500)
  private String filename;

  @Column(name = "mime_type", length = 200)
  private String mimeType;

  @Column(name = "file_size")
  private Long fileSize;

  @Column(name = "sha256", length = 64)
  private String sha256;

  @Column(name = "minio_path", length = 1000)
  private String minioPath;

  @Column(name = "extraction_method", length = 50)
  private String extractionMethod;

  /** Non-null when the file was detected but not stored (e.g. "exceeds_size_limit"). */
  @Column(name = "skipped_reason", length = 100)
  private String skippedReason;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;
}
