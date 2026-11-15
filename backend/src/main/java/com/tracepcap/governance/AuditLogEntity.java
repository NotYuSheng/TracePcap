package com.tracepcap.governance;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** One audited change (#915). Append-only. See V48. */
@Entity
@Table(name = "audit_log")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "at", nullable = false)
  private LocalDateTime at;

  @Column(name = "actor", nullable = false)
  private String actor;

  @Column(name = "action", nullable = false)
  private String action;

  @Column(name = "target_type", nullable = false)
  private String targetType;

  @Column(name = "target_id")
  private String targetId;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "before_value", columnDefinition = "jsonb")
  private Map<String, Object> before;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "after_value", columnDefinition = "jsonb")
  private Map<String, Object> after;
}
