package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Records how much each internal host transferred with each external endpoint (#813): one {@code
 * communicates-with} edge per host→external pair carrying the total bytes, for pairs above a
 * threshold so the board stays focused on significant transfers. This is the volume signal a
 * data-transfer check reads to tell a bulk transfer to a real destination from ordinary CDN
 * traffic. MEASURED — it is a property of the traffic itself.
 */
@Component
@RequiredArgsConstructor
public class TrafficContributor implements KnowledgeContributor {

  /** Only pairs that moved at least this many bytes become an edge — keeps the board focused. */
  static final long MIN_BYTES = 100_000;

  static final String COMMUNICATES_WITH = "communicates-with";

  private final ConversationLookup conversationLookup;

  @Override
  public String name() {
    return "traffic";
  }

  @Override
  public void contribute(UUID fileId, CaseKnowledgeBuilder board) {
    // internal host -> (external ip -> total bytes)
    Map<String, Map<String, Long>> bytesByPair = new LinkedHashMap<>();
    for (ConversationFacts conv : conversationLookup.conversationFacts(fileId)) {
      String a = conv.flow().srcIp();
      String b = conv.flow().dstIp();
      if (a == null || b == null) continue;
      boolean aLocal = IpLocality.isLocal(a);
      boolean bLocal = IpLocality.isLocal(b);
      // Only host <-> external pairs; skip internal-internal and external-external.
      String host;
      String external;
      if (aLocal && !bLocal) {
        host = a;
        external = b;
      } else if (bLocal && !aLocal) {
        host = b;
        external = a;
      } else {
        continue;
      }
      bytesByPair
          .computeIfAbsent(host, k -> new LinkedHashMap<>())
          .merge(external, conv.flow().totalBytes(), Long::sum);
    }

    bytesByPair.forEach(
        (host, peers) ->
            peers.forEach(
                (external, bytes) -> {
                  if (bytes < MIN_BYTES) return;
                  board.addRelationship(
                      new Relationship(
                          EntityRef.host(host),
                          COMMUNICATES_WITH,
                          EntityRef.external(external),
                          Grade.MEASURED,
                          name(),
                          Map.of("bytes", bytes)));
                }));
  }
}
