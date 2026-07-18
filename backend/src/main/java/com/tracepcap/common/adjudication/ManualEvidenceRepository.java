package com.tracepcap.common.adjudication;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Persistence for {@link ManualEvidenceEntity} (append-only), keyed by the adjudicated question. */
public interface ManualEvidenceRepository extends JpaRepository<ManualEvidenceEntity, Long> {

  /** All evidence for one question in one file — an adjudicator folds this into its vote. */
  List<ManualEvidenceEntity> findByQuestionAndFileId(String question, UUID fileId);

  /** Evidence for one entity, newest first, for display in the reasons trail. */
  List<ManualEvidenceEntity> findByQuestionAndFileIdAndEntityKeyOrderByCreatedAtDesc(
      String question, UUID fileId, String entityKey);
}
