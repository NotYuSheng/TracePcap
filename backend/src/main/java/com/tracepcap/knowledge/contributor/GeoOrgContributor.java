package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.analysis.spi.GeoOrgLookup.IpAttribution;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Attribution for the external endpoints that carry an IDS alert (#813): country, ASN, and org from
 * the offline GeoIP database. Bounded to alerted externals so the board stays focused; the geo
 * attributes merge onto the same {@code EXTERNAL_SERVICE} entities the IDS contributor posts, so a
 * check answering "what is the C2?" can name where it is hosted. All INFERRED — a third party's
 * opinion about who owns a range.
 */
@Component
@RequiredArgsConstructor
public class GeoOrgContributor implements KnowledgeContributor {

  private final ConversationLookup conversationLookup;
  private final GeoOrgLookup geoOrgLookup;

  @Override
  public String name() {
    return "geo-org";
  }

  @Override
  public void contribute(UUID fileId, CaseKnowledgeBuilder board) {
    Set<String> externals = new LinkedHashSet<>();
    for (ConversationFacts conv : conversationLookup.conversationFacts(fileId)) {
      var alerts = conv.findings().suricataAlerts();
      if (alerts == null || alerts.isEmpty()) continue;
      addExternal(externals, conv.flow().srcIp());
      addExternal(externals, conv.flow().dstIp());
    }
    if (externals.isEmpty()) return;

    Map<String, IpAttribution> attribution = geoOrgLookup.attributionFor(externals);
    for (String ip : externals) {
      IpAttribution a = attribution.get(ip);
      if (a == null) continue;
      Map<String, Object> attrs = new LinkedHashMap<>();
      put(attrs, "country", a.countryCode());
      put(attrs, "asn", a.asn());
      put(attrs, "org", a.org());
      if (!attrs.isEmpty()) board.addEntity(EntityRef.external(ip), attrs);
    }
  }

  private void addExternal(Set<String> set, String ip) {
    if (ip != null && !ip.isBlank() && !IpLocality.isLocal(ip)) set.add(ip);
  }

  private static void put(Map<String, Object> attrs, String key, String value) {
    if (value != null && !value.isBlank()) attrs.put(key, value);
  }
}
