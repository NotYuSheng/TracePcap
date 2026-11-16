package com.tracepcap.story.chat.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.tracepcap.cluster.service.NetworkClusterService;
import com.tracepcap.story.chat.ChatTool;
import com.tracepcap.story.service.LlmToolSpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class DnsLookupsTool implements ChatTool {

  private final NetworkClusterService cluster;

  public String name() { return "dns_lookups"; }
  public String label() { return "DNS lookups"; }
  public String summary() { return "names looked up, and the answers"; }
  public String example() { return "What resolves to 194.25.0.68?"; }

  public LlmToolSpec spec() {
    return new LlmToolSpec(name(),
        "Names looked up through each DNS server in the capture, with the response code, the"
            + " addresses returned and how often. Filter by part of a name, by an address an answer"
            + " returned, or by the DNS server. The log is per server: it does not say which client asked.",
        LlmToolSpec.schema()
            .property("name", "string", "Part of the name looked up, e.g. 'example.com'.")
            .property("answer", "string", "An IP address one of the answers returned.")
            .property("server", "string", "Only this DNS server's log.")
            .property("failedOnly", "boolean", "True for only lookups that failed (NXDOMAIN and the like).")
            .property("limit", "integer", "How many to return (default 20, at most 60).")
            .build());
  }

  public Result run(ChatToolContext ctx, JsonNode args) {
    String name = ToolArgs.text(args, "name");
    String answer = ToolArgs.text(args, "answer");
    String server = ToolArgs.text(args, "server");
    boolean failedOnly = Boolean.TRUE.equals(ToolArgs.bool(args, "failedOnly"));
    int limit = ToolArgs.limit(args, 20, 60);
    var servers = cluster.computeDnsServers(ctx.fileId());
    List<Map<String, Object>> rows = new ArrayList<>();
    int total = 0;
    for (var s : servers) {
      if (server != null && !server.equals(s.getServerIp())) continue;
      var log = cluster.computeDnsQueryLog(ctx.fileId(), s.getServerIp());
      if (log == null || log.getEntries() == null) continue;
      for (var e : log.getEntries()) {
        if (name != null && (e.getQueryName() == null || !e.getQueryName().toLowerCase().contains(name.toLowerCase()))) continue;
        if (answer != null && (e.getResolvedIps() == null || !e.getResolvedIps().contains(answer))) continue;
        if (failedOnly && e.isResolvable()) continue;
        total++;
        if (rows.size() >= limit) continue;
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("server", s.getServerIp());
        r.put("name", e.getQueryName());
        r.put("type", e.getQueryType());
        r.put("response", e.getResponseCode());
        r.put("answers", e.getResolvedIps());
        r.put("count", e.getQueryCount());
        rows.add(r);
      }
    }
    return Result.of(total + (total == 1 ? " lookup" : " lookups") + " across " + servers.size()
        + (servers.size() == 1 ? " DNS server" : " DNS servers"),
        Map.of("total", total, "lookups", rows));
  }
}
