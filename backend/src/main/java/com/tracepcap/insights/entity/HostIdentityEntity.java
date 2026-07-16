package com.tracepcap.insights.entity;

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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * The adjudicated identity of one host in one capture (#512 slice 5): a winner with confidence,
 * or an explicitly contested outcome with the competing candidates. Versioned and revisable —
 * re-adjudication overwrites the row on analysis completion or node-role change.
 */
@Entity
@Table(name = "host_identities")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HostIdentityEntity {

  public static final String BASIS_HUMAN = "HUMAN";
  public static final String BASIS_MACHINE = "MACHINE";

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  /** The one answer to "what is this host?" — device type, or the human's label verbatim. */
  @Column(name = "primary_label", nullable = false, length = 100)
  private String primaryLabel;

  /** HUMAN (confirmed node-role label, ranked first) or MACHINE (classification vote). */
  @Column(nullable = false, length = 20)
  private String basis;

  @Column(nullable = false)
  private int confidence;

  /** True when competing machine candidates were too close to call — see {@code candidates}. */
  @Column(nullable = false)
  private boolean contested;

  /** JSON array [{label, source, score}] of the competing candidates when contested. */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(columnDefinition = "jsonb")
  private String candidates;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
