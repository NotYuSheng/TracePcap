package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Read port for per-file conversation facts (#512 slice 6): the MEASURED core of the fact base,
 * served without exposing the {@code analysis} module's repositories or JPA entities. Started for
 * timeline binning; the record grows fields as further consumers (report, intelligence, story)
 * migrate onto it — additive growth only, implementors live inside {@code analysis}.
 */
public interface ConversationLookup {

  record ConversationFacts(
      String protocol,
      LocalDateTime startTime,
      LocalDateTime endTime,
      long packetCount,
      long totalBytes) {}

  List<ConversationFacts> conversationFacts(UUID fileId);
}
