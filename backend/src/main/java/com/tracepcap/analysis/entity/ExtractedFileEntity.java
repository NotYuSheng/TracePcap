package com.tracepcap.analysis.entity;

import com.tracepcap.file.entity.FileEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "extracted_files")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExtractedFileEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id", nullable = false)
  private FileEntity file;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "conversation_id")
  private ConversationEntity conversation;

  @Column(name = "filename", length = 500)
  private String filename;

  @Column(name = "mime_type", length = 200)
  private String mimeType;

  @Column(name = "file_size")
  private Long fileSize;

  @Column(name = "sha256", length = 64)
  private String sha256;

  @Column(name = "minio_path", length = 1000, nullable = false)
  private String minioPath;

  @Column(name = "extraction_method", length = 50)
  private String extractionMethod;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;
}
