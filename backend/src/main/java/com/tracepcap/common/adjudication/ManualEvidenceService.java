package com.tracepcap.common.adjudication;

import com.tracepcap.common.event.AdjudicationOverriddenEvent;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.security.CurrentActor;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * Appends analyst evidence to an adjudicated question and re-runs adjudication so it takes effect.
 *
 * <p>Question-agnostic; the actor is stamped server-side from {@link CurrentActor}. The weight is
 * clamped to {@code [1, MAX_WEIGHT]}: analyst evidence is a strong signal but must not be able to
 * swamp the machine vote into meaninglessness — a human who is certain uses an override, not an
 * enormous weight.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ManualEvidenceService {

  /**
   * Upper bound on a single piece of evidence's weight. Chosen to sit on the order of the classifier
   * signals it competes with (which contribute tens of points), so evidence can tip a close contest
   * without trivialising it. Certainty belongs in an override, not an unbounded weight.
   */
  public static final int MAX_WEIGHT = 100;

  private final ManualEvidenceRepository repository;
  private final CurrentActor currentActor;
  private final ApplicationEventPublisher eventPublisher;

  /** Evidence for one entity, newest first — for the reasons trail. */
  public List<ManualEvidenceEntity> forEntity(String question, UUID fileId, String entityKey) {
    return repository.findByQuestionAndFileIdAndEntityKeyOrderByCreatedAtDesc(
        question, fileId, entityKey);
  }

  /**
   * Records a weighted piece of evidence toward {@code label} and re-runs adjudication. The reason
   * is required — evidence with no stated reason is not evidence, it is an unexplained nudge.
   */
  @Transactional
  public ManualEvidenceEntity append(
      String question, UUID fileId, String entityKey, String label, int weight, String reason) {
    int clamped = Math.max(1, Math.min(MAX_WEIGHT, weight));
    ManualEvidenceEntity entity =
        ManualEvidenceEntity.builder()
            .question(question)
            .fileId(fileId)
            .entityKey(entityKey)
            .label(label)
            .weight(clamped)
            .reason(reason)
            .actor(currentActor.username()) // server-side, from the token
            .build();
    ManualEvidenceEntity saved = repository.save(entity);
    log.info(
        "Manual evidence: {} '{}' (+{}) for {} in file {} by {}",
        question, label, clamped, entityKey, fileId, saved.getActor());
    eventPublisher.publishEvent(new AdjudicationOverriddenEvent(fileId));
    return saved;
  }

  /**
   * Updates the analyst's own evidence (label/weight/reason) and re-runs adjudication. Only the
   * original author may edit their evidence; anyone else gets 403. The evidence must belong to the
   * addressed {@code (question, fileId, entityKey)} — an id under mismatched coordinates is treated
   * as not found, never silently edited.
   */
  @Transactional
  public ManualEvidenceEntity update(
      String question, UUID fileId, String entityKey, Long id, String label, int weight, String reason) {
    ManualEvidenceEntity e = loadOwnedOrThrow(question, fileId, entityKey, id);
    e.setLabel(label);
    e.setWeight(Math.max(1, Math.min(MAX_WEIGHT, weight)));
    e.setReason(reason);
    ManualEvidenceEntity saved = repository.save(e);
    log.info("Manual evidence {} edited by {} in file {}", id, saved.getActor(), saved.getFileId());
    eventPublisher.publishEvent(new AdjudicationOverriddenEvent(saved.getFileId()));
    return saved;
  }

  /** Deletes the analyst's own evidence and re-runs adjudication. Author-only; others get 403. */
  @Transactional
  public void delete(String question, UUID fileId, String entityKey, Long id) {
    ManualEvidenceEntity e = loadOwnedOrThrow(question, fileId, entityKey, id);
    repository.delete(e);
    log.info("Manual evidence {} deleted by {} in file {}", id, currentActor.username(), fileId);
    eventPublisher.publishEvent(new AdjudicationOverriddenEvent(fileId));
  }

  /**
   * Loads evidence by id, asserts it belongs to the addressed question/file/entity, and asserts the
   * current actor is its author. Evidence is a personal statement — only the analyst who made it may
   * change or retract it. A "system" actor (auth off) may manage system-authored evidence, keeping
   * the auth-disabled path usable. A coordinate mismatch is a plain 404: the id does not exist
   * <em>at that address</em>, and answering 403/409 would leak that it exists elsewhere.
   */
  private ManualEvidenceEntity loadOwnedOrThrow(
      String question, UUID fileId, String entityKey, Long id) {
    ManualEvidenceEntity e =
        repository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Evidence", "id", id));
    if (!e.getQuestion().equals(question)
        || !e.getFileId().equals(fileId)
        || !e.getEntityKey().equals(entityKey)) {
      throw new ResourceNotFoundException("Evidence", "id", id);
    }
    if (!currentActor.username().equals(e.getActor())) {
      throw new ResponseStatusException(
          HttpStatus.FORBIDDEN, "Only the original author can edit or delete this evidence");
    }
    return e;
  }
}
