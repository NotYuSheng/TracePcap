package com.tracepcap.story.chat.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.tracepcap.analysis.spi.AnalysisSummaryLookup;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.story.chat.ChatTool;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.service.FindingsService;
import com.tracepcap.story.service.LlmToolSpec;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class FindingsTool implements ChatTool {

  private final FindingsService findings;
  private final AnalysisSummaryLookup summaries;
  private final ConversationLookup conversations;

  public String name() { return "get_findings"; }
  public String label() { return "Findings"; }
  public String summary() { return "by severity, type or host"; }
  public String example() { return "What's critical in this capture?"; }

  public LlmToolSpec spec() {
    return new LlmToolSpec(name(),
        "The capture's deterministic findings (beacons, fan-out, long sessions, risk flags and more),"
            + " most serious first. Filter by severity, finding type or an IP address.",
        LlmToolSpec.schema()
            .enumProperty("severity", "Only this severity.", List.of("CRITICAL", "HIGH", "MEDIUM", "LOW"))
            .property("type", "string", "Only this finding type, e.g. BEACON, FAN_OUT, LONG_SESSION.")
            .property("ip", "string", "Only findings that involve this IP address.")
            .property("limit", "integer", "How many to return (default 10, at most 30).")
            .build());
  }

  public Result run(ChatToolContext ctx, JsonNode args) {
    var s = summaries.summaryFor(ctx.fileId()).orElse(null);
    long convs = conversations.conversationCount(ctx.fileId());
    List<Finding> all = findings.detectAll(ctx.fileId(), convs, s == null ? 0 : s.totalBytes(), ctx.networkId());
    String sev = ToolArgs.text(args, "severity");
    String type = ToolArgs.text(args, "type");
    String ip = ToolArgs.text(args, "ip");
    List<Finding> hits = all.stream()
        .filter(f -> sev == null || (f.getSeverity() != null && f.getSeverity().name().equalsIgnoreCase(sev)))
        .filter(f -> type == null || (f.getType() != null && f.getType().name().equalsIgnoreCase(type.replace(' ', '_'))))
        .filter(f -> ip == null || (f.getAffectedIps() != null && f.getAffectedIps().contains(ip)))
        .toList();
    int limit = ToolArgs.limit(args, 10, 30);
    List<Map<String, Object>> rows = hits.stream().limit(limit).map(f -> {
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("severity", f.getSeverity());
      m.put("type", f.getType());
      m.put("title", f.getTitle());
      m.put("summary", f.getSummary());
      m.put("affectedIps", f.getAffectedIps());
      if (f.getMetrics() != null) m.put("metrics", f.getMetrics());
      return m;
    }).toList();
    String first = hits.isEmpty() ? "" : ": " + hits.get(0).getTitle();
    return Result.of(hits.size() + (hits.size() == 1 ? " finding" : " findings") + first,
        Map.of("total", hits.size(), "findings", rows));
  }
}
