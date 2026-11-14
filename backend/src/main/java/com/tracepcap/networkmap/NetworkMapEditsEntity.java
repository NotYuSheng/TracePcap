package com.tracepcap.networkmap;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** One capture's network map edits (#649). */
@Entity
@Table(name = "network_map_edits")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkMapEditsEntity {

  @Id
  @Column(name = "file_id")
  private UUID fileId;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "edits", columnDefinition = "jsonb", nullable = false)
  private NetworkMapEdits edits;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Column(name = "updated_by")
  private String updatedBy;
}
