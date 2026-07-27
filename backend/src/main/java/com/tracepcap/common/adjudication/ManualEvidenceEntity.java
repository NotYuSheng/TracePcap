package com.tracepcap.common.adjudication;

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
import org.hibernate.annotations.CreationTimestamp;

/**
 * One piece of analyst-appended evidence for an adjudicated question — a weighted vote toward a
 * candidate, with a reason the analyst supplied.
 *
 * <p><b>It informs the vote; it does not decide it.</b> Unlike a {@link HumanOverrideEntity} (which
 * IS the answer), evidence re-enters the machine vote as one more weighted input and appears in the
 * reasons trail tagged analyst-provided. An analyst who leans the scale still sees an honest contest
 * if the machine genuinely disagrees — the thumb on the scale is visible, not hidden.
 *
 * <p>Append-only and question-agnostic (keyed by {@code (question, fileId, entityKey)}), carrying
 * its own audit trail ({@link #actor} resolved server-side, {@link #createdAt}).
 */
@Entity
@Table(name = "manual_evidence")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ManualEvidenceEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  /** The {@code Adjudicator.question()} this evidence bears on. */
  @Column(nullable = false, length = 64)
  private String question;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "entity_key", nullable = false, length = 255)
  private String entityKey;

  /** Which candidate this evidence supports (a device type, or any candidate label). */
  @Column(nullable = false, length = 100)
  private String label;

  /** How strongly the analyst weights it (bounded in {@link ManualEvidenceService}). */
  @Column(nullable = false)
  private int weight;

  /** The analyst's reason, shown verbatim in the reasons trail. */
  @Column(nullable = false, columnDefinition = "TEXT")
  private String reason;

  /** Who added it (audit): the authenticated username, or {@code "system"} when auth is off. */
  @Column(nullable = false, length = 255)
  private String actor;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;
}
