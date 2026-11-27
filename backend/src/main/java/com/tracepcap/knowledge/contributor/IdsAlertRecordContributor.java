package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.IdsAlertLookup;
import com.tracepcap.analysis.spi.IdsAlertLookup.IdsAlertFacts;
import com.tracepcap.common.net.LocalityRules;
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
  /** Absent when the records stopped at their cap before this server's last alert (#1284). */
  public static final String LAST_ALERT = "lastAlert";
  /** Set only when fewer records were kept than alerts fired (#1284): how many were. */
  public static final String ALERT_RECORDS_KEPT = "alertRecordsKept";
  /**
   * In place of {@link #FIRST_ALERT} when the records were cut (#1284): the earliest record kept.
   * The capture's cap cuts in log order, so an earlier alert on another flow may have no record.
   */
  public static final String FIRST_KEPT_ALERT = "firstKeptAlert";
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
    post(lookup.forFile(context.fileId()), lookup.countsForFile(context.fileId()), context.locality(),
        board);
  }

  static void post(List<IdsAlertFacts> records, LocalityRules local, CaseKnowledgeBuilder board) {
    post(records, List.of(), local, board);
  }

  /** The board-facing part, unit-testable without a lookup. */
  static void post(
      List<IdsAlertFacts> records, List<IdsAlertLookup.AlertCount> counts, LocalityRules local,
      CaseKnowledgeBuilder board) {
    Map<String, List<IdsAlertFacts>> byExternal = new LinkedHashMap<>();
    for (IdsAlertFacts a : records) {
      String external = externalOf(a.srcIp(), a.dstIp(), local);
      if (external != null) byExternal.computeIfAbsent(external, k -> new ArrayList<>()).add(a);
    }
    // The true counts (#1284), when the capture has them: the records may be only the first.
    Map<String, Integer> totals = new LinkedHashMap<>();
    for (IdsAlertLookup.AlertCount c : counts) {
      String external = externalOf(c.srcIp(), c.dstIp(), local);
      if (external == null) continue;
      totals.merge(external, c.total(), Integer::sum);
      byExternal.computeIfAbsent(external, k -> new ArrayList<>()); // every record cut, still counted
    }
    byExternal.forEach((external, list) -> {
      Map<String, Object> attrs = new LinkedHashMap<>();
      int total = Math.max(totals.getOrDefault(external, 0), list.size());
      boolean truncated = total > list.size();
      attrs.put(ALERT_COUNT, total);
      if (truncated) attrs.put(ALERT_RECORDS_KEPT, list.size());
      LocalDateTime first = null, last = null;
      Map<String, Integer> requests = new LinkedHashMap<>();
      for (IdsAlertFacts a : list) {
        if (a.time() != null) {
          if (first == null || a.time().isBefore(first)) first = a.time();
          if (last == null || a.time().isAfter(last)) last = a.time();
        }
        String r = request(a, local);
        if (r != null) requests.merge(r, 1, Integer::sum);
      }
      if (first != null) attrs.put(truncated ? FIRST_KEPT_ALERT : FIRST_ALERT, TrafficContributor.utc(first));
      // Past the cap, the last record kept isn't the last alert. Request counts are of the records
      // kept: ALERT_RECORDS_KEPT says so.
      if (last != null && !truncated) attrs.put(LAST_ALERT, TrafficContributor.utc(last));
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

  /**
   * "Alerts fired on: POST http://… (65×)", from a server's attributes; null when none were HTTP.
   * Once its records were cut (#1284) the counts are of the records kept, and the line says so.
   */
  public static String requestsLine(Map<String, Object> server) {
    if (!(server.get(ALERT_REQUESTS) instanceof List<?> reqs) || reqs.isEmpty()) return null;
    Object kept = server.get(ALERT_RECORDS_KEPT);
    return (kept != null
            ? "Of the " + kept + " alert records kept, the HTTP requests they fired on"
                + (reqs.size() >= MAX_REQUESTS ? " (most frequent first)" : "") + ": "
            : "Alerts fired on: ")
        + String.join(", ", reqs.stream().map(String::valueOf).toList());
  }

  /**
   * Copies a server's request list into an answer's attributes, with the true count and how many
   * records were kept when they were cut (#1284), so a reader of the attributes isn't misled either.
   */
  public static void putRequests(Map<String, Object> server, Map<String, Object> attrs) {
    if (server.get(ALERT_REQUESTS) == null) return;
    attrs.put("requests", server.get(ALERT_REQUESTS));
    if (server.get(ALERT_RECORDS_KEPT) != null) {
      attrs.put(ALERT_COUNT, server.get(ALERT_COUNT));
      attrs.put(ALERT_RECORDS_KEPT, server.get(ALERT_RECORDS_KEPT));
    }
  }

  /**
   * "65 alerts from … to …"; when the records stopped at their cap (#1284), the true count and how
   * many records were kept, since neither the first nor the last record kept is then certain to be
   * the first or last alert.
   */
  public static String alertSpan(Map<String, Object> ent) {
    Object n = ent.get(ALERT_COUNT);
    String count = n == null ? "Alerts" : n + " alert" + ("1".equals(String.valueOf(n)) ? "" : "s");
    Object kept = ent.get(ALERT_RECORDS_KEPT);
    if (kept != null) {
      Object firstKept = ent.get(FIRST_KEPT_ALERT);
      return count + " (" + ("0".equals(String.valueOf(kept)) ? "no records kept"
          : "records kept for " + kept + " of them only"
              + (firstKept != null ? ", the earliest at " + TrafficContributor.readable(firstKept) : ""))
          + ")";
    }
    Object first = ent.get(FIRST_ALERT);
    if (first == null) return null;
    Object last = ent.get(LAST_ALERT);
    return count + " from " + TrafficContributor.readable(first)
        + (last != null ? " to " + TrafficContributor.readable(last) : "");
  }

  /** The outside side of an alert between a local host and the outside; null otherwise. */
  private static String externalOf(String srcIp, String dstIp, LocalityRules local) {
    if (srcIp == null || dstIp == null) return null;
    boolean srcLocal = local.isLocal(srcIp), dstLocal = local.isLocal(dstIp);
    if (srcLocal == dstLocal) return null;
    return srcLocal ? dstIp : srcIp;
  }

  /** "METHOD absolute-url" for an HTTP alert; null when it wasn't HTTP. */
  static String request(IdsAlertFacts a, LocalityRules local) {
    if (a.httpUrl() == null || a.httpUrl().isBlank()) return null;
    String url = a.httpUrl().trim();
    if (!url.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) {
      String host = a.httpHost() != null && !a.httpHost().isBlank()
          ? a.httpHost().trim()
          : local.isLocal(a.srcIp()) ? a.dstIp() : a.srcIp();
      url = "http://" + host + (url.startsWith("/") ? "" : "/") + url;
    }
    return (a.httpMethod() == null ? "" : a.httpMethod() + " ") + url;
  }
}
