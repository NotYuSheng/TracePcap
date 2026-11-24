package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Every Suricata alert as it was logged (#1265), for other modules: the conversation detail and the
 * knowledge layer. {@link ConversationLookup}'s {@code suricataAlerts} stays the deduplicated
 * message list; this is the record behind it.
 */
public interface IdsAlertLookup {

  /**
   * One alert.
   *
   * @param srcIp the side that sent the packet that fired it: for a "response" rule, the server
   * @param signatureSeverity the rule's own metadata ("Critical", "Major", "Minor", "Informational")
   * @param confidence the rule's own metadata ("High", "Medium", "Low")
   * @param metadata the rule's whole metadata block, key → values
   * @param httpUrl the request the alert fired on, when it was HTTP
   */
  record IdsAlertFacts(
      UUID conversationId,
      LocalDateTime time,
      String srcIp,
      Integer srcPort,
      String dstIp,
      Integer dstPort,
      long sid,
      Integer rev,
      String signature,
      String category,
      Integer severity,
      String signatureSeverity,
      String confidence,
      String attackTarget,
      Map<String, List<String>> metadata,
      String httpMethod,
      String httpHost,
      String httpUrl,
      String httpUserAgent,
      Integer httpStatus) {}

  /** One Suricata protocol anomaly (#1268): traffic a parser found malformed or one-sided. */
  record AnomalyFacts(
      LocalDateTime time, String srcIp, String dstIp, String type, String layer, String appProto,
      String event) {}

  /** A conversation's protocol anomalies, oldest first. */
  List<AnomalyFacts> anomaliesFor(UUID conversationId);

  /** A conversation's alerts, oldest first. */
  List<IdsAlertFacts> forConversation(UUID conversationId);

  /** A capture's alerts, oldest first. */
  List<IdsAlertFacts> forFile(UUID fileId);
}
