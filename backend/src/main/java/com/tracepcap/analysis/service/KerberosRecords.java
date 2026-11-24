package com.tracepcap.analysis.service;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads Suricata's {@code krb5} records (#1267): each ticket a domain controller issued, with its
 * encryption, and each error it returned, with the account it was about. The account and service
 * attacks (password spraying, user enumeration, an RC4 ticket from a KDC that uses AES) show here
 * and nowhere else in the analysis.
 *
 * <p>Suricata leaves the account name empty on a {@code KRB_ERROR}, so an error takes it from the
 * request it answers: the last one on the same flow. Requests themselves aren't kept. Like the SMB
 * records, which side is the client comes from the port (the KDC is on 88), not from the record:
 * Suricata logs a stream it picked up mid-way server-first.
 */
final class KerberosRecords {

  private KerberosRecords() {}

  static final int MAX_EXCHANGES = 20_000;

  /** A KDC's port. */
  static final int KDC_PORT = 88;

  static final String ERROR = "KRB_ERROR";

  /** One reply as Suricata logged it, with the account and service of the request it answers. */
  record Reply(
      LocalDateTime time, String msgType, String account, String service, String realm,
      String errorCode, String encryption, boolean weak) {}

  /** One kind of reply on a conversation, grouped, with which side asked. */
  public record Exchange(
      LocalDateTime firstTime, String client, String kdc, String msgType, String account,
      String service, String realm, String errorCode, String encryption, boolean weak, int count) {}

  static boolean mayBe(String line) {
    return line.contains("\"event_type\":\"krb5\"");
  }

  /**
   * Reads one record. {@code requests} remembers the last request on each flow so an error can name
   * its account; {@code count} is a running total for the cap.
   */
  static void read(
      JsonNode root, String flowKey, Map<String, List<Reply>> replies,
      java.util.concurrent.atomic.AtomicInteger count, Map<String, JsonNode> requests) {
    JsonNode k = root.path("krb5");
    String type = k.path("msg_type").asText("");
    String flowId = root.path("flow_id").asText("");
    if (type.endsWith("_REQ")) {
      // Without a flow id a request can't be matched to its reply; the map is bounded too.
      if (!flowId.isEmpty() && requests.size() < MAX_EXCHANGES) requests.put(flowId, k);
      return;
    }
    if (!type.endsWith("_REP") && !ERROR.equals(type)) return;
    if (count.get() >= MAX_EXCHANGES) return;
    // The reply consumes its request, so a later error on the flow can't inherit a stale account.
    JsonNode req = flowId.isEmpty() ? null : requests.remove(flowId);
    String account = name(k, "cname");
    if (account == null && req != null) account = name(req, "cname");
    String service = name(k, "sname");
    if (service == null && req != null) service = name(req, "sname");
    String realm = name(k, "realm");
    if (realm == null && req != null) realm = name(req, "realm");
    replies.computeIfAbsent(flowKey, x -> new ArrayList<>()).add(new Reply(
        SuricataService.eveTime(root.path("timestamp").asText(null)), cut(type, 32), account, service,
        realm, cut(name(k, "error_code"), 64), ERROR.equals(type) ? null : cut(name(k, "encryption"), 64),
        k.path("weak_encryption").asBoolean(false)));
    count.incrementAndGet();
  }

  /** To its column's width (V83), so one odd value can't fail the file's whole write. */
  private static String cut(String s, int max) {
    return s == null || s.length() <= max ? s : s.substring(0, max);
  }

  /** Suricata writes "<empty>" and "<none>" for a missing value. */
  private static String name(JsonNode n, String field) {
    JsonNode v = n.path(field);
    if (v.isMissingNode() || v.isNull()) return null;
    String s = v.asText("").trim();
    if (s.isEmpty() || s.equals("<empty>") || s.equals("<none>")) return null;
    return s.length() > 255 ? s.substring(0, 255) : s;
  }

  /** Groups a conversation's replies. The KDC is the side on port 88; else the conversation's server. */
  static List<Exchange> group(
      List<Reply> replies, String srcIp, Integer srcPort, String dstIp, Integer dstPort) {
    boolean srcIsKdc = srcPort != null && srcPort == KDC_PORT && (dstPort == null || dstPort != KDC_PORT);
    String client = srcIsKdc ? dstIp : srcIp, kdc = srcIsKdc ? srcIp : dstIp;
    Map<List<Object>, Exchange> grouped = new LinkedHashMap<>();
    for (Reply r : replies) {
      List<Object> key = java.util.Arrays.asList(
          r.msgType(), r.account(), r.service(), r.errorCode(), r.encryption(), r.weak());
      Exchange prev = grouped.get(key);
      LocalDateTime first = prev == null ? r.time()
          : prev.firstTime() == null || (r.time() != null && r.time().isBefore(prev.firstTime()))
              ? r.time() : prev.firstTime();
      grouped.put(key, new Exchange(first, client, kdc, r.msgType(), r.account(), r.service(),
          r.realm(), r.errorCode(), r.encryption(), r.weak(), prev == null ? 1 : prev.count() + 1));
    }
    return new ArrayList<>(grouped.values());
  }
}
