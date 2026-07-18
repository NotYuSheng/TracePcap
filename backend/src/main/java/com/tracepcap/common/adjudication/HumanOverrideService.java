package com.tracepcap.common.adjudication;

import com.tracepcap.common.event.AdjudicationOverriddenEvent;
import com.tracepcap.config.security.CurrentActor;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The one place a human override is written or cleared, for any adjudicated question.
 *
 * <p>Question-agnostic: callers pass the {@code Adjudicator.question()} string. The actor is stamped
 * server-side from {@link CurrentActor} — never from the request — and every change publishes
 * {@link AdjudicationOverriddenEvent} so the {@link com.tracepcap.common.stage.Adjudicator}s re-run
 * and the conclusion reflects the human's answer immediately.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HumanOverrideService {

  private final HumanOverrideRepository repository;
  private final CurrentActor currentActor;
  private final ApplicationEventPublisher eventPublisher;

  /** The current override for one question about one entity, if a human has set one. */
  public Optional<HumanOverrideEntity> find(String question, UUID fileId, String entityKey) {
    return repository.findByQuestionAndFileIdAndEntityKey(question, fileId, entityKey);
  }

  /**
   * Sets (or replaces) the human's answer to {@code question} about {@code entityKey} in this file,
   * attributing it to the current actor, then re-runs adjudication. Idempotent on the unique key.
   */
  @Transactional
  public HumanOverrideEntity override(
      String question, UUID fileId, String entityKey, String label, String rationale) {
    HumanOverrideEntity entity =
        repository
            .findByQuestionAndFileIdAndEntityKey(question, fileId, entityKey)
            .orElseGet(
                () ->
                    HumanOverrideEntity.builder()
                        .question(question)
                        .fileId(fileId)
                        .entityKey(entityKey)
                        .build());
    entity.setLabel(label);
    entity.setRationale(rationale);
    entity.setActor(currentActor.username()); // server-side, from the token — never the client
    HumanOverrideEntity saved = repository.save(entity);
    log.info(
        "Human override: {} '{}' for {} in file {} by {}",
        question, label, entityKey, fileId, saved.getActor());
    eventPublisher.publishEvent(new AdjudicationOverriddenEvent(fileId));
    return saved;
  }

  /** Removes the human's answer, letting the machine vote decide again. Re-runs adjudication. */
  @Transactional
  public void clear(String question, UUID fileId, String entityKey) {
    repository.deleteByQuestionAndFileIdAndEntityKey(question, fileId, entityKey);
    log.info("Human override cleared: {} for {} in file {}", question, entityKey, fileId);
    eventPublisher.publishEvent(new AdjudicationOverriddenEvent(fileId));
  }
}
