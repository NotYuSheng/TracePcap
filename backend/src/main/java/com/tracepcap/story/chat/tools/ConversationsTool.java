package com.tracepcap.story.chat.tools;

import com.tracepcap.common.net.Endpoints;
import com.fasterxml.jackson.databind.JsonNode;
import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.story.chat.ChatTool;
import com.tracepcap.story.service.LlmToolSpec;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class ConversationsTool implements ChatTool {

  private final ConversationLookup conversations;

  public String name() { return "find_conversations"; }
  public String label() { return "Conversations"; }
  public String summary() { return "by host, port, protocol, app or flag; busiest first"; }
  public String example() { return "Who talked to 194.25.0.68?"; }

  public LlmToolSpec spec() {
    return new LlmToolSpec(name(),
        "Conversations (flows) in the capture matching every filter given, the most bytes first."
            + " Give at least one filter.",
        LlmToolSpec.schema()
            .property("ip", "string", "An IP address at either end.")
            .property("port", "integer", "A port at either end.")
            .property("protocol", "string", "Transport protocol: TCP, UDP or ICMP.")
            .property("app", "string", "Application as nDPI named it, e.g. DNS, TLS, HTTP.")
            .property("flagged", "boolean", "True for only conversations nDPI flagged with a risk.")
            .property("riskType", "string", "Only conversations with this nDPI risk, e.g. unsafe_protocol.")
            .property("limit", "integer", "How many to return (default 15, at most 50).")
            .build());
  }

  public Result run(ChatToolContext ctx, JsonNode args) {
    String ip = ToolArgs.text(args, "ip");
    Integer port = ToolArgs.integer(args, "port");
    String protocol = ToolArgs.text(args, "protocol");
    String app = ToolArgs.text(args, "app");
    Boolean flagged = ToolArgs.bool(args, "flagged");
    String risk = ToolArgs.text(args, "riskType");
    if (ip == null && port == null && protocol == null && app == null && !Boolean.TRUE.equals(flagged) && risk == null) {
      throw new IllegalArgumentException("Give at least one filter: ip, port, protocol, app, flagged or riskType.");
    }
    var filter = ConversationFilterParams.builder()
        .ip(ip).port(port)
        .protocols(protocol == null ? List.of() : List.of(protocol.toUpperCase()))
        .apps(app == null ? List.of() : List.of(app))
        .hasRisks(Boolean.TRUE.equals(flagged) ? true : null)
        .riskTypes(risk == null ? List.of() : List.of(risk))
        .l7Protocols(List.of()).categories(List.of()).fileTypes(List.of()).customSignatures(List.of())
        .suricataAlerts(List.of()).deviceTypes(List.of()).countries(List.of())
        .build();
    List<ConversationFacts> hits = new ArrayList<>(conversations.conversationFacts(ctx.fileId(), filter));
    hits.sort(Comparator.comparingLong((ConversationFacts c) -> c.flow().totalBytes()).reversed());
    int limit = ToolArgs.limit(args, 15, 50);
    long bytes = hits.stream().mapToLong(c -> c.flow().totalBytes()).sum();
    List<Map<String, Object>> rows = hits.stream().limit(limit).map(ConversationsTool::row).toList();
    return Result.of(hits.size() + (hits.size() == 1 ? " conversation" : " conversations") + ", " + bytes + " bytes",
        Map.of("total", hits.size(), "totalBytes", bytes, "conversations", rows));
  }

  static Map<String, Object> row(ConversationFacts c) {
    var f = c.flow();
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("src", Endpoints.of(f.srcIp(), f.srcPort()));
    m.put("dst", Endpoints.of(f.dstIp(), f.dstPort()));
    m.put("protocol", f.protocol());
    if (c.findings() != null && c.findings().appName() != null) m.put("app", c.findings().appName());
    m.put("packets", f.packetCount());
    m.put("bytes", f.totalBytes());
    m.put("start", f.startTime());
    m.put("end", f.endTime());
    if (c.findings() != null && c.findings().flowRisks() != null && !c.findings().flowRisks().isEmpty())
      m.put("risks", c.findings().flowRisks());
    if (c.tls() != null && c.tls().hostname() != null) m.put("sni", c.tls().hostname());
    return m;
  }
}
