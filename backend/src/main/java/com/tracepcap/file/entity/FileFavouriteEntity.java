package com.tracepcap.file.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** One account's favourite capture. */
@Entity
@Table(name = "file_favourites")
@IdClass(FileFavouriteEntity.Key.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class FileFavouriteEntity {

  @Id
  @Column(name = "profile_key", nullable = false, length = 255)
  private String profileKey;

  @Id
  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "created_at", nullable = false)
  private LocalDateTime createdAt;

  /** The composite key: one row per account and capture. */
  @Getter
  @Setter
  @NoArgsConstructor
  @AllArgsConstructor
  @EqualsAndHashCode
  public static class Key implements Serializable {
    private String profileKey;
    private UUID fileId;
  }
}
