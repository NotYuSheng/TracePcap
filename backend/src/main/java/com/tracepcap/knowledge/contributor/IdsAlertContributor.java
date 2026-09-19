package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Posts Suricata IDS hits as board findings — the other fact the STRRAT demo showed Story mode was
 * missing. Each flagged conversation becomes an {@code ids-alert} finding concerning both endpoints,
 * with a {@code communicates-with} relationship from the internal host to the external service and,
 * where the signature names a family (e.g. STRRAT), a malware entity. "What is the C2?" then becomes
 * a query over these findings, not a metric-based guess.
 */
@Component
@RequiredArgsConstructor
public class IdsAlertContributor implements KnowledgeContributor {

  static final String IDS_ALERT = "ids-alert";
  static final String COMMUNICATES_WITH = "communicates-with";
  static final String C2_OF = "c2-of";

  /** "ET MALWARE STRRAT CnC Checkin (sid:2030358 sev:1)" → captures the family token after MALWARE. */
  private static final Pattern MALWARE_FAMILY =
      Pattern.compile("\\bMALWARE\\s+([A-Z0-9_]{2,})\\b");

  private final ConversationLookup conversationLookup;

  @Override
  public String name() {
    return "ids-alerts";
  }

  @Override
  public void contribute(UUID fileId, CaseKnowledgeBuilder board) {
    for (ConversationFacts conv : conversationLookup.conversationFacts(fileId)) {
      List<String> alerts = conv.findings().suricataAlerts();
      if (alerts == null || alerts.isEmpty()) continue;

      String srcIp = conv.flow().srcIp();
      String dstIp = conv.flow().dstIp();
      EntityRef srcRef = endpointRef(srcIp);
      EntityRef dstRef = endpointRef(dstIp);
      if (srcRef == null || dstRef == null) continue;

      // The external party is the non-local endpoint; direct the C2 edge internal → external.
      boolean srcLocal = IpLocality.isLocal(srcIp);
      EntityRef internal = srcLocal ? srcRef : dstRef;
      EntityRef external = srcLocal ? dstRef : srcRef;

      board.addRelationship(
          Relationship.of(internal, COMMUNICATES_WITH, external, Grade.MEASURED, name()));

      for (String alert : alerts) {
        board.addFinding(
            new Finding(
                IDS_ALERT,
                alert,
                Severity.CRITICAL,
                Grade.INFERRED,
                "suricata",
                List.of(srcRef, dstRef),
                List.of(conv.id().toString()),
                Map.of("srcIp", srcIp, "dstIp", dstIp)));

        String family = malwareFamily(alert);
        if (family != null) {
          EntityRef malwareRef = EntityRef.malware(family);
          board.addEntity(malwareRef);
          // The external endpoint is this malware's C2.
          board.addRelationship(
              Relationship.of(external, C2_OF, malwareRef, Grade.INFERRED, "suricata"));
        }
      }
    }
  }

  /** A host if internal, an external service if routable; null for a blank/unusable address. */
  private EntityRef endpointRef(String ip) {
    if (ip == null || ip.isBlank()) return null;
    return IpLocality.isLocal(ip) ? EntityRef.host(ip) : EntityRef.external(ip);
  }

  private String malwareFamily(String alert) {
    if (alert == null) return null;
    Matcher m = MALWARE_FAMILY.matcher(alert);
    return m.find() ? m.group(1) : null;
  }
}
