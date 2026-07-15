package com.tracepcap.analysis.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One extractor run for one file — the persistence side of the extraction manifest
 * ({@link com.tracepcap.analysis.spi.ExtractionManifest}). Unique per (file, extractor);
 * re-analysis replaces the row.
 */
@Entity
@Table(name = "extraction_runs")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExtractionRunEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 50)
  private String extractor;

  @Column(nullable = false, length = 20)
  private String version;

  @Column(nullable = false, length = 20)
  private String status;

  @Column(columnDefinition = "TEXT")
  private String detail;

  @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
  private LocalDateTime createdAt;
}
