package com.tracepcap.common.adjudication;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

/**
 * A human's final answer to one adjudicated question about one entity — the generic override that
 * every {@link com.tracepcap.common.stage.Adjudicator} consults before it votes.
 *
 * <p><b>Question-agnostic on purpose.</b> Keyed by {@code (question, fileId, entityKey)} — the same
 * coordinates every adjudicator already works in — so a new adjudicated question inherits override
 * by reading this table under its own {@code question()} key, with no new table and no new endpoint.
 *
 * <p><b>It outranks the machine.</b> When a row exists for an adjudicator's question and entity, that
 * label IS the answer: basis HUMAN, confidence 100, never contested. "The analyst has spoken."
 *
 * <p><b>It carries its own audit trail.</b> {@link #actor} + {@link #createdAt} record who overrode
 * and when. The actor is resolved server-side from the token (see
 * {@link com.tracepcap.config.security.CurrentActor}); it is never taken from the request body.
 */
@Entity
@Table(
    name = "human_overrides",
    uniqueConstraints =
        @UniqueConstraint(
            name = "uq_human_override",
            columnNames = {"question", "file_id", "entity_key"}))
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HumanOverrideEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  /** The {@code Adjudicator.question()} this override answers, e.g. {@code "host-identity"}. */
  @Column(nullable = false, length = 64)
  private String question;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  /** The host/IP/MAC this answer is about. */
  @Column(name = "entity_key", nullable = false, length = 255)
  private String entityKey;

  /** The human's answer — replaces whatever the machine concluded. */
  @Column(nullable = false, length = 100)
  private String label;

  /** Why they overrode (optional, free text). */
  @Column(columnDefinition = "TEXT")
  private String rationale;

  /** Who overrode (audit): the authenticated username, or {@code "system"} when auth is off. */
  @Column(nullable = false, length = 255)
  private String actor;

  /**
   * MANUAL when the human set this override directly on this file; CARRIED_FORWARD when it was copied
   * from the previous monitor snapshot and re-validated (#499). Carried rows are regenerated per
   * snapshot by {@code OverrideStalenessService}.
   */
  @Builder.Default
  @Column(name = "origin", nullable = false, length = 20)
  private String origin = "MANUAL";

  /** Baseline of the classifying properties when carried, diffed against the new pcap to detect drift. */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "observed_properties", columnDefinition = "jsonb")
  private Map<String, Object> observedProperties;

  /** When this carried override first drifted from its baseline; sticky until re-affirmed or cleared. */
  @Column(name = "stale_since")
  private LocalDateTime staleSince;

  /** The human-readable changes that made it stale (e.g. "MAC changed (… → …)"). */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "stale_fields", columnDefinition = "jsonb")
  private List<String> staleFields;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
