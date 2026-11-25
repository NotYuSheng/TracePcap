package com.tracepcap.knowledge.dto;

import com.tracepcap.knowledge.service.CategoryCatalogue;
import java.util.List;

/**
 * API view of one investigation-framework category: where it sits, how much of it a capture can
 * show, the standard questions that answer it, and the traffic they read.
 */
public record InvestigationCategoryResponse(
    String key,
    String axis,
    String label,
    String attackId,
    String visibility,
    String unseenReason,
    List<String> questions,
    List<EvidenceResponse> evidence) {

  /** Traffic one question reads: tshark and nDPI names, and what it shows for that question. */
  public record EvidenceResponse(
      String question, String label, List<String> l7, List<String> apps, String shows, boolean byL7) {}

  public static InvestigationCategoryResponse from(CategoryCatalogue.Entry e) {
    var c = e.category();
    return new InvestigationCategoryResponse(
        c.key(),
        c.axis().name(),
        c.label(),
        c.attackId(),
        c.visibility().name(),
        c.unseenReason(),
        e.questions(),
        e.evidence().stream()
            .map(q -> new EvidenceResponse(q.question(), q.source().label(), q.source().l7(),
                q.source().apps(), q.source().shows(), q.source().byL7()))
            .toList());
  }
}
