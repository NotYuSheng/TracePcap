package com.tracepcap.common.adjudication;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Persistence for {@link HumanOverrideEntity}, keyed by the adjudicated question. */
public interface HumanOverrideRepository extends JpaRepository<HumanOverrideEntity, Long> {

  /** Every override for one question in one file — an adjudicator loads this to apply precedence. */
  List<HumanOverrideEntity> findByQuestionAndFileId(String question, UUID fileId);

  /** The override for one entity, if a human has answered this question about it. */
  Optional<HumanOverrideEntity> findByQuestionAndFileIdAndEntityKey(
      String question, UUID fileId, String entityKey);

  void deleteByQuestionAndFileIdAndEntityKey(String question, UUID fileId, String entityKey);

  /** Remove regenerable carried-forward overrides for a question in a file (#499 monitor carry-forward). */
  void deleteByQuestionAndFileIdAndOrigin(String question, UUID fileId, String origin);
}
