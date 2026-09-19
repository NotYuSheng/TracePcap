package com.tracepcap.knowledge.service;

import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Assembles the knowledge board for a capture by running every {@link KnowledgeContributor} into one
 * shared {@link CaseKnowledgeBuilder} (#813). Contributors are auto-discovered — Spring injects the
 * whole list — so adding a source needs no change here.
 *
 * <p>Each contributor is isolated: one that throws is logged and skipped, and the board is still
 * assembled from the rest. Today the board is computed on read from the existing {@code
 * analysis.spi} lookups; materialising it is a later concern (see the RFC's open questions).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CaseKnowledgeService {

  private final List<KnowledgeContributor> contributors;

  /** Runs every contributor and returns the assembled board. Never throws for a single bad source. */
  public CaseKnowledge assemble(UUID fileId) {
    CaseKnowledgeBuilder board = new CaseKnowledgeBuilder(fileId);
    for (KnowledgeContributor contributor : contributors) {
      try {
        contributor.contribute(fileId, board);
      } catch (Exception e) {
        log.warn(
            "Knowledge contributor '{}' failed for file {}: {}",
            contributor.name(),
            fileId,
            e.getMessage());
      }
    }
    CaseKnowledge knowledge = board.build();
    log.info(
        "Assembled knowledge for file {}: {} entit(ies), {} relationship(s), {} finding(s) from {} contributor(s)",
        fileId,
        knowledge.entities().size(),
        knowledge.relationships().size(),
        knowledge.findings().size(),
        contributors.size());
    return knowledge;
  }
}
