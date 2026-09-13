package com.tracepcap.insights.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * The adjudicated Windows identity of one host in one capture (#809): a winner with confidence, or
 * an explicitly contested outcome with the competing candidates — same shape as {@link
 * HostIdentityEntity}, but answering "who is logged into this host?" rather than "what is this
 * host?". Versioned and revisable: re-adjudication overwrites the row on analysis completion.
 *
 * <p>Absence is meaningful here in a way it is not for {@code host_identities}: every host has
 * <em>some</em> device type, but not every host has an observed Windows identity, so a host with no
 * claims gets no row rather than a synthesized "unknown" one.
 */
@Entity
@Table(name = "windows_identities")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WindowsIdentityEntity {

  public static final String BASIS_HUMAN = "HUMAN";
  public static final String BASIS_MACHINE = "MACHINE";

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  /** The one answer to "who is this?" — a username/real name, or the human's label verbatim. */
  @Column(name = "primary_label", nullable = false, length = 255)
  private String primaryLabel;

  /** HUMAN (override, ranked first) or MACHINE (Kerberos/LDAP claim). */
  @Column(nullable = false, length = 20)
  private String basis;

  @Column(nullable = false)
  private int confidence;

  /** True when multiple distinct usernames were claimed for this IP — see {@code candidates}. */
  @Column(nullable = false)
  private boolean contested;

  /** Competing/corroborating candidates [{label, source, score}]; Hibernate maps the JSON. */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(columnDefinition = "jsonb")
  private List<Map<String, Object>> candidates;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
