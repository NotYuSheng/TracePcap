package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.IdsAlertLookup;
import com.tracepcap.analysis.spi.IdsAlertLookup.IdsAlertFacts;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.KnowledgeContext;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Summarises each outside server's Suricata alerts from the full records (#1265): how many fired,
 * the first and last in UTC, and the HTTP requests they fired on, the IOC an incident report lists
 * ("POST http://194.180.191.64/fakeurl.htm"). Posted as attributes of the external entity, so any
 * answer about that server can cite them.
 */
@Component
public class IdsAlertRecordContributor implements KnowledgeContributor {

  public static final String ALERT_COUNT = "alertCount";
  public static final String FIRST_ALERT = "firstAlert";
  public static final String LAST_ALERT = "lastAlert";
  /** "POST http://host/path (65×)", most frequent first, at most {@link #MAX_REQUESTS}. */
  public static final String ALERT_REQUESTS = "alertRequests";

  static final int MAX_REQUESTS = 5;

  /** Looked up when needed: a context without analysis (a test, a slice) still works. */
  private final ObjectProvider<IdsAlertLookup> alerts;

  public IdsAlertRecordContributor(ObjectProvider<IdsAlertLookup> alerts) {
    this.alerts = alerts;
  }

  @Override
  public String name() {
    return "ids-alert-records";
  }

  @Override
  public void contribute(KnowledgeContext context, CaseKnowledgeBuilder board) {
    IdsAlertLookup lookup = alerts.getIfAvailable();
    if (lookup == null) return;
    post(lookup.forFile(context.fileId()), board);
  }

  /** The board-facing part, unit-testable without a lookup. */
  static void post(List<IdsAlertFacts> records, CaseKnowledgeBuilder board) {
    Map<String, List<IdsAlertFacts>> byExternal = new LinkedHashMap<>();
    for (IdsAlertFacts a : records) {
      String external = externalOf(a);
      if (external != null) byExternal.computeIfAbsent(external, k -> new ArrayList<>()).add(a);
    }
    byExternal.forEach((external, list) -> {
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put(ALERT_COUNT, list.size());
      LocalDateTime first = null, last = null;
      Map<String, Integer> requests = new LinkedHashMap<>();
      for (IdsAlertFacts a : list) {
        if (a.time() != null) {
          if (first == null || a.time().isBefore(first)) first = a.time();
          if (last == null || a.time().isAfter(last)) last = a.time();
        }
        String r = request(a);
        if (r != null) requests.merge(r, 1, Integer::sum);
      }
      if (first != null) attrs.put(FIRST_ALERT, TrafficContributor.utc(first));
      if (last != null) attrs.put(LAST_ALERT, TrafficContributor.utc(last));
      if (!requests.isEmpty()) {
        attrs.put(
            ALERT_REQUESTS,
            requests.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(MAX_REQUESTS)
                .map(e -> e.getKey() + (e.getValue() > 1 ? " (" + e.getValue() + "×)" : ""))
                .toList());
      }
      board.addEntity(EntityRef.external(external), attrs);
    });
  }

  /** The outside side of an alert between a local host and the outside; null otherwise. */
  private static String externalOf(IdsAlertFacts a) {
    if (a.srcIp() == null || a.dstIp() == null) return null;
    boolean srcLocal = IpLocality.isLocal(a.srcIp()), dstLocal = IpLocality.isLocal(a.dstIp());
    if (srcLocal == dstLocal) return null;
    return srcLocal ? a.dstIp() : a.srcIp();
  }

  /** "METHOD absolute-url" for an HTTP alert; null when it wasn't HTTP. */
  static String request(IdsAlertFacts a) {
    if (a.httpUrl() == null || a.httpUrl().isBlank()) return null;
    String url = a.httpUrl().trim();
    if (!url.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) {
      String host = a.httpHost() != null && !a.httpHost().isBlank()
          ? a.httpHost().trim()
          : IpLocality.isLocal(a.srcIp()) ? a.dstIp() : a.srcIp();
      url = "http://" + host + (url.startsWith("/") ? "" : "/") + url;
    }
    return (a.httpMethod() == null ? "" : a.httpMethod() + " ") + url;
  }
}
