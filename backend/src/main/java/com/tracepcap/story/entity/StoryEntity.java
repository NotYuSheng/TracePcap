package com.tracepcap.story.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

/** Entity representing a generated story/narrative for a PCAP file */
@Entity
@Table(name = "stories")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StoryEntity {

  @Id private UUID id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "generated_at", nullable = false)
  private LocalDateTime generatedAt;

  @Column(name = "content", nullable = false, columnDefinition = "TEXT")
  private String content; // JSON content containing narrative, highlights, and timeline

  @Column(name = "model_used", length = 100)
  private String modelUsed;

  @Column(name = "tokens_used")
  private Integer tokensUsed;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @Column(name = "status", nullable = false, length = 50)
  @Enumerated(EnumType.STRING)
  private StoryStatus status;

  @Column(name = "error_message", columnDefinition = "TEXT")
  private String errorMessage;

  /** Story generation status */
  public enum StoryStatus {
    GENERATING,
    COMPLETED,
    FAILED
  }
}
